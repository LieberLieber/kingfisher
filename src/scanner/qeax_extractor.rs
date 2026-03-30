use std::fmt::Write as FmtWrite;
use std::path::Path;

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OpenFlags};
use tracing::debug;

const MAX_ROWS_PER_TABLE: usize = 100_000;
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;

/// List of Sparx Enterprise Architect tables to scan for secrets
/// Based on user recommendations for comprehensive EA repository scanning
const EA_TABLES: &[&str] = &[
    // Core object/element records and properties
    "t_object",           // Element names, notes, descriptions
    "t_objectproperties", // Element tagged values (endpoints, credentials, etc.)
    
    // Document/content storage
    "t_document",         // Linked documents and large embedded content
    
    // Attribute definitions and tagged values
    "t_attribute",        // Attribute definitions and notes
    "t_attributetag",     // Attribute tagged values
    
    // Operation/method definitions and tagged values
    "t_operation",        // Method/operation definitions and notes
    "t_operationtag",     // Method tagged values
    "t_operationparams",  // Parameter definitions
    
    // Generic tagged values (parameters, association ends)
    "t_taggedvalue",      // Parameter tags and role tags
    
    // Connector/relationship information
    "t_connectortag",     // Connector tagged values
    "t_connector",        // Relationships, names, descriptions
    
    // Additional context and metadata
    "t_xref",             // Cross-references and custom metadata
];

/// Extract Enterprise Architect-specific tables from a .qeax file (SQLite database).
///
/// Returns a vec of `(logical_name, sql_text)` pairs, one per EA table.
/// Each entry contains the CREATE TABLE statement followed by INSERT statements.
///
/// Special handling for the "<memo>" pattern:
/// When a column's value is the literal string "<memo>", the Notes column
/// content is substituted inline so pattern matching sees the real secret.
pub fn extract_qeax_contents(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("Failed to open .qeax file (SQLite database): {}", path.display()))?;

    conn.busy_timeout(std::time::Duration::from_secs(5))?;

    // Verify this looks like an EA database by checking for at least one EA table
    verify_ea_database(&conn)?;

    let mut results = Vec::with_capacity(EA_TABLES.len());
    let mut total_bytes: usize = 0;

    for table_name in EA_TABLES {
        if total_bytes >= MAX_TOTAL_BYTES {
            debug!(
                "EA extraction hit total size limit ({MAX_TOTAL_BYTES} bytes), \
                 skipping remaining tables in {}",
                path.display()
            );
            break;
        }

        // Check if table exists in this database
        if !table_exists(&conn, table_name)? {
            debug!("EA table '{}' not found in {}", table_name, path.display());
            continue;
        }

        let create_sql = get_create_table_sql(&conn, table_name)?;

        match dump_table_with_memo_resolution(&conn, table_name, &create_sql, MAX_TOTAL_BYTES - total_bytes) {
            Ok(sql_text) => {
                total_bytes += sql_text.len();
                let logical_name = format!("{}.sql", table_name);
                results.push((logical_name, sql_text.into_bytes()));
            }
            Err(e) => {
                debug!("Failed to dump EA table '{}' from {}: {e:#}", table_name, path.display());
            }
        }
    }

    if results.is_empty() {
        bail!(
            "No Enterprise Architect tables found in {}. \
            This file may not be a valid .qeax (Sparx EA) repository.",
            path.display()
        );
    }

    Ok(results)
}

/// Verify that this database contains at least one EA table.
fn verify_ea_database(conn: &Connection) -> Result<()> {
    for table_name in EA_TABLES {
        if table_exists(conn, table_name)? {
            return Ok(());
        }
    }
    bail!(
        "Database does not contain any expected Enterprise Architect tables. \
        This may not be a valid .qeax file."
    );
}

/// Check if a table exists in the database
fn table_exists(conn: &Connection, table_name: &str) -> Result<bool> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
    )?;
    let exists = stmt.exists([table_name])?;
    Ok(exists)
}

/// Get the CREATE TABLE statement for a table
fn get_create_table_sql(conn: &Connection, table_name: &str) -> Result<String> {
    let mut stmt = conn.prepare(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
    )?;
    let sql = stmt.query_row([table_name], |row| row.get(0))?;
    Ok(sql)
}

/// Dump a single table as SQL text with special handling for the "<memo>" pattern.
///
/// For columns that contain the value "<memo>", this function attempts to resolve
/// it by looking up the Notes column. This is documented in Sparx EA as a way to
/// store long values: Value = "<memo>" with actual content in Notes.
fn dump_table_with_memo_resolution(
    conn: &Connection,
    table_name: &str,
    create_sql: &str,
    remaining_budget: usize,
) -> Result<String> {
    let mut out = String::with_capacity(4096);
    let create_statement = format!("{create_sql};\n");
    if !push_with_budget(&mut out, &create_statement, remaining_budget) {
        bail!(
            "CREATE TABLE statement for '{table_name}' exceeds remaining size budget ({remaining_budget} bytes)"
        );
    }

    let col_names = column_names(conn, table_name)?;
    if col_names.is_empty() {
        return Ok(out);
    }

    let columns_fragment =
        col_names.iter().map(|c| sqlite_quoted_identifier(c)).collect::<Vec<_>>().join(",");

    let quoted_table_name = sqlite_quoted_identifier(table_name);
    let query = format!("SELECT * FROM {quoted_table_name}");
    let mut stmt = conn.prepare(&query)?;
    let col_count = col_names.len();

    // Check if this table has a Notes column for memo resolution
    let notes_col_idx = col_names.iter().position(|c| c == "Notes");

    let mut rows_emitted: usize = 0;
    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        if rows_emitted >= MAX_ROWS_PER_TABLE {
            let marker = format!("-- (truncated after {MAX_ROWS_PER_TABLE} rows)\n");
            let _ = push_with_budget(&mut out, &marker, remaining_budget);
            break;
        }
        if out.len() >= remaining_budget {
            break;
        }

        let mut row_sql = String::new();
        write!(row_sql, "INSERT INTO {quoted_table_name} ({columns_fragment}) VALUES (")?;

        for i in 0..col_count {
            if i > 0 {
                write!(row_sql, ",")?;
            }
            
            // Check if this value is "<memo>" and we have a Notes column
            if let Some(notes_idx) = notes_col_idx {
                if is_memo_value(&row, i)? {
                    // Try to resolve from Notes column
                    if let Ok(notes_value) = row.get_ref(notes_idx) {
                        write_value(&mut row_sql, notes_value)?;
                    } else {
                        // If Notes lookup fails, write the "<memo>" literally
                        write!(row_sql, "'<memo>'")?;
                    }
                } else {
                    write_value_from_row(&mut row_sql, row, i)?;
                }
            } else {
                write_value_from_row(&mut row_sql, row, i)?;
            }
        }

        writeln!(row_sql, ");")?;
        if !push_with_budget(&mut out, &row_sql, remaining_budget) {
            let marker = "-- (truncated: size limit reached)\n";
            let _ = push_with_budget(&mut out, marker, remaining_budget);
            break;
        }
        rows_emitted += 1;
    }

    Ok(out)
}

/// Check if a row value at the given index is the "<memo>" marker
fn is_memo_value(row: &rusqlite::Row<'_>, idx: usize) -> Result<bool> {
    use rusqlite::types::ValueRef;
    match row.get_ref(idx)? {
        ValueRef::Text(t) => {
            let s = String::from_utf8_lossy(t);
            Ok(s == "<memo>")
        }
        _ => Ok(false),
    }
}

fn push_with_budget(out: &mut String, fragment: &str, remaining_budget: usize) -> bool {
    if out.len().saturating_add(fragment.len()) > remaining_budget {
        return false;
    }
    out.push_str(fragment);
    true
}

fn column_names(conn: &Connection, table_name: &str) -> Result<Vec<String>> {
    let query = format!("PRAGMA table_info({})", sqlite_quoted_identifier(table_name));
    let mut stmt = conn.prepare(&query)?;
    let names = stmt
        .query_map([], |row| {
            let name: String = row.get(1)?;
            Ok(name)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names)
}

fn sqlite_quoted_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn write_value_from_row(out: &mut String, row: &rusqlite::Row<'_>, idx: usize) -> Result<()> {
    let value_ref = row.get_ref(idx)?;
    write_value(out, value_ref)?;
    Ok(())
}

fn write_value(out: &mut String, value_ref: rusqlite::types::ValueRef<'_>) -> Result<()> {
    use rusqlite::types::ValueRef;
    match value_ref {
        ValueRef::Null => write!(out, "NULL")?,
        ValueRef::Integer(i) => write!(out, "{i}")?,
        ValueRef::Real(f) => write!(out, "{f}")?,
        ValueRef::Text(t) => {
            let s = String::from_utf8_lossy(t);
            write!(out, "'{}'", s.replace('\'', "''"))?;
        }
        ValueRef::Blob(b) => {
            write!(out, "X'")?;
            for byte in b {
                write!(out, "{byte:02X}")?;
            }
            write!(out, "'")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn create_test_qeax() -> (NamedTempFile, std::path::PathBuf) {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let conn = Connection::open(&path).unwrap();
        
        // Create minimal EA schema
        conn.execute_batch(
            "CREATE TABLE t_object (
                ObjectID INTEGER PRIMARY KEY,
                Name TEXT,
                Notes TEXT
            );
            INSERT INTO t_object VALUES (1, 'TestElement', 'This has a secret: aws_secret_access_key=AKIAIOSFODNN7EXAMPLE');
            
            CREATE TABLE t_objectproperties (
                PropertyID INTEGER PRIMARY KEY,
                ObjectID INTEGER,
                Property TEXT,
                Value TEXT,
                Notes TEXT
            );
            INSERT INTO t_objectproperties VALUES (1, 1, 'endpoint', '<memo>', 'https://api.example.com/token?key=ghp_abc123def456');
            INSERT INTO t_objectproperties VALUES (2, 1, 'api_key', 'sk_test_123456789', NULL);",
        )
        .unwrap();
        (tmp, path)
    }

    #[test]
    fn extracts_ea_tables() {
        let (_tmp, path) = create_test_qeax();
        let results = extract_qeax_contents(&path).unwrap();
        
        // Should extract the EA tables that exist
        assert!(!results.is_empty());
        
        // Find t_object and t_objectproperties
        let t_object = results.iter().find(|(name, _)| name == "t_object.sql");
        let t_props = results.iter().find(|(name, _)| name == "t_objectproperties.sql");
        
        assert!(t_object.is_some());
        assert!(t_props.is_some());
    }

    #[test]
    fn resolves_memo_pattern() {
        let (_tmp, path) = create_test_qeax();
        let results = extract_qeax_contents(&path).unwrap();
        
        // Get t_objectproperties
        let (_name, data) = results.iter().find(|(n, _)| n == "t_objectproperties.sql").unwrap();
        let sql_text = String::from_utf8(data.clone()).unwrap();
        
        // The memo value should be resolved to the Notes content
        assert!(sql_text.contains("https://api.example.com/token?key=ghp_abc123def456"));
        // Should NOT contain just the literal "<memo>"
        assert!(!sql_text.contains("'<memo>'"));
    }

    #[test]
    fn fails_on_invalid_qeax() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let conn = Connection::open(&path).unwrap();
        
        // Create a database with no EA tables
        conn.execute_batch(
            "CREATE TABLE random_table (id INTEGER PRIMARY KEY, data TEXT);"
        )
        .unwrap();
        drop(conn);
        
        // Should fail with descriptive error
        let result = extract_qeax_contents(&path);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("Enterprise Architect"));
    }
}
