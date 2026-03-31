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
    // === CORE ELEMENT TABLES ===
    "t_object",           // Element names, notes, descriptions, Stereotype
    "t_objectproperties", // Element tagged values (endpoints, credentials, configs)
    "t_objectconstraint", // Object constraints with notes
    // === DIAGRAM & VISUAL STRUCTURE ===
    "t_diagram",        // Diagram metadata and notes (CRITICAL for diagram-level secrets)
    "t_diagramobjects", // Objects placed on diagrams with names/annotations
    "t_diagramlinks",   // Connections/links on diagrams
    "t_diagramtypes",   // Diagram type definitions
    // === DOCUMENT & CONTENT STORAGE ===
    "t_document", // Linked documents and embedded content
    "t_html",     // HTML-formatted content storage
    "t_rtf",      // Rich text formatted content
    "t_files",    // File references, paths, and metadata
    "t_image",    // Image metadata and descriptions
    // === ATTRIBUTES & PARAMETERS ===
    "t_attribute",            // Attribute definitions and notes
    "t_attributetag",         // Attribute tagged values
    "t_attributeconstraints", // Attribute constraints with notes
    "t_taggedvalue",          // Parameter tags, role tags, generic key-value data
    "t_operationparams",      // Operation parameter definitions
    // === OPERATIONS, METHODS & SCRIPTS ===
    "t_operation",    // Method/operation definitions and notes
    "t_operationtag", // Operation tagged values
    "t_method",       // Method/implementation details
    "t_script",       // Scripts, code, script notes (CRITICAL for code-based secrets)
    // === CONNECTORS & RELATIONSHIPS ===
    "t_connector",           // Relationships/associations with names, descriptions
    "t_connectortag",        // Connector tagged values
    "t_connectorconstraint", // Connector constraints
    "t_connectortypes",      // Connector type definitions
    // === TYPES & CLASSIFICATIONS ===
    "t_objecttypes",     // Object type definitions
    "t_datatypes",       // Data type definitions
    "t_cardinality",     // Cardinality definitions
    "t_constrainttypes", // Constraint type definitions
    "t_stereotypes",     // Stereotype definitions and descriptions
    "t_category",        // Category definitions and descriptions
    // === RULES & CONSTRAINTS ===
    "t_rules",     // Rules and associated notes
    "t_constants", // Constants with values and notes
    // === RESOURCE & PROJECT MANAGEMENT ===
    "t_resources",    // Resource descriptions
    "t_projectroles", // Project role definitions
    "t_phase",        // Phase definitions and descriptions
    "t_version",      // Version/release/baseline information and notes
    "t_snapshot",     // Snapshot metadata and descriptions
    // === ISSUES, RISKS & PROBLEMS ===
    "t_issues",         // Issue tracking with descriptions
    "t_tasks",          // Task descriptions and notes
    "t_objectrisks",    // Risk descriptions and notes
    "t_objectproblems", // Problem descriptions and notes
    // === TESTING & REQUIREMENTS ===
    "t_testclass",      // Test class definitions
    "t_testplans",      // Test plan information
    "t_requiretypes",   // Requirement type definitions
    "t_objectrequires", // Requirement descriptions
    "t_objecttests",    // Test descriptions
    // === BUSINESS & DOCUMENTATION ===
    "t_glossary",   // Business glossary definitions (IMPORTANT text source)
    "t_package",    // Package descriptions and notes
    "t_implement",  // Implementation descriptions
    "t_umlpattern", // UML pattern descriptions
    "t_template",   // Template descriptions and content
    // === EFFORT & METRICS ===
    "t_objectmetrics",   // Metric descriptions and notes
    "t_objecteffort",    // Effort estimation and descriptions
    "t_objectscenarios", // Scenario descriptions
    "t_objecttrx",       // Traceability information
    // === ADDITIONAL METADATA ===
    "t_xref",  // Cross-references and custom metadata
    "t_lists", // Enumeration lists and values (may contain secrets)
    // === ENTERPRISE ARCHITECT SYSTEM TABLES (Non-standard but sometimes present) ===
    "t_propertytypes", // Property type definitions
    "t_mainttypes",    // Maintenance type definitions
    "t_efforttypes",   // Effort type definitions
    "t_organizetypes", // Organization type definitions
    "t_risktypes",     // Risk type definitions
    "t_problemtypes",  // Problem type definitions
    "t_scenariotypes", // Scenario type definitions
    "t_statustypes",   // Status type definitions
    "t_testtypes",     // Test type definitions
    "t_trxtypes",      // Traceability type definitions
    // === SECURITY & USER MANAGEMENT ===
    "t_seclocks",      // Security locks information
    "t_secgroup",      // Security group definitions
    "t_secuser",       // Security user information
    "t_secusergroup",  // User group assignments
    "t_secpermission", // Permission definitions
    "t_secpolicies",   // Security policy definitions
];

/// Extract Enterprise Architect-specific tables from a .qeax file (SQLite database).
///
/// For t_object table: Groups elements by package (parent_id) and creates separate "documents"
/// for each package using their fully qualified hierarchical names. This treats packages like
/// file containers, enabling better context for secret discovery.
///
/// Returns a vec of `(logical_name, sql_text)` pairs, one per EA table or package.
pub fn extract_qeax_contents(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let conn =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).with_context(|| {
            format!("Failed to open .qeax file (SQLite database): {}", path.display())
        })?;

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

        // Special handling for t_object: group by package hierarchy
        if table_name == &"t_object" {
            match extract_t_object_by_packages(&conn, MAX_TOTAL_BYTES - total_bytes) {
                Ok(package_documents) => {
                    for (logical_name, sql_bytes) in package_documents {
                        total_bytes += sql_bytes.len();
                        results.push((logical_name, sql_bytes));
                        if total_bytes >= MAX_TOTAL_BYTES {
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to extract t_object by packages: {e:#}");
                }
            }
        }

        // Skip extracting t_package separately: we already extract packages through
        // extract_t_object_by_packages(), which groups t_objects by their parent package.
        // Each package becomes its own file with all its child objects.
        // Skipping this prevents duplicate extraction and avoids exposing package metadata
        // that may contain sensitive information.
        if table_name == &"t_package" {
            debug!("Skipping t_package table extraction (handled via extract_t_object_by_packages)");
            continue;
        }

        // Standard extraction for other tables
        let create_sql = get_create_table_sql(&conn, table_name)?;
        match dump_table_with_memo_resolution(
            &conn,
            table_name,
            &create_sql,
            MAX_TOTAL_BYTES - total_bytes,
        ) {
            Ok(sql_text) => {
                total_bytes += sql_text.len();
                let logical_name = format!("{}.sql", table_name);
                results.push((logical_name, sql_text.into_bytes()));
            }
            Err(e) => {
                debug!(
                    "Failed to dump EA table '{}' from {}: {e:#}",
                    table_name,
                    path.display()
                );
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

    // Debug: log all extracted files
    debug!("QEAX extraction complete: {} files generated", results.len());
    for (logical_name, sql_bytes) in &results {
        debug!("  - {}: {} bytes", logical_name, sql_bytes.len());
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
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1")?;
    let exists = stmt.exists([table_name])?;
    Ok(exists)
}

/// Get the CREATE TABLE statement for a table
fn get_create_table_sql(conn: &Connection, table_name: &str) -> Result<String> {
    let mut stmt =
        conn.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1")?;
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

    // For t_object table, we can enhance output with hierarchy information
    let is_t_object = table_name == "t_object";

    while let Some(row) = rows.next()? {
        if rows_emitted >= MAX_ROWS_PER_TABLE {
            let marker = format!("-- (truncated after {MAX_ROWS_PER_TABLE} rows)\n");
            let _ = push_with_budget(&mut out, &marker, remaining_budget);
            break;
        }
        if out.len() >= remaining_budget {
            break;
        }

        // For t_object rows, try to add hierarchy context as a comment
        if is_t_object {
            // Attempt to get ObjectID (usually first column) and Name (usually second)
            if let (Ok(obj_id), Ok(obj_name)) = (row.get::<_, i64>(0), row.get::<_, String>(1)) {
                if let Ok(hierarchy) = build_element_hierarchy(conn, obj_id, &obj_name) {
                    let comment = format!("-- HIERARCHY: {}\n", hierarchy);
                    let _ = push_with_budget(&mut out, &comment, remaining_budget);
                }
            }
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

/// Build the fully qualified hierarchical name for an EA element.
///
/// For an element within packages, returns a path like "Company::IT::Systems::DatabaseServer"
/// by traversing the package hierarchy. If the element has no package or hierarchy resolution
/// fails, returns just the element name.
///
/// This provides better context for discovered secrets and enables filtering by business domain.
/// Build the fully qualified hierarchical name for a package from t_package hierarchy.
///
/// Traverses the t_package.Parent_ID chain to build complete package path.
/// Returns path like "Company::IT::Systems" by traversing Parent_ID relationships.
fn build_package_hierarchy(
    conn: &Connection,
    package_id: i64,
    package_name: &str,
) -> Result<String> {
    let mut path_parts = vec![package_name.to_string()];
    let mut current_id = package_id;
    let mut seen_ids = std::collections::HashSet::new();

    // Traverse up the package hierarchy using Parent_ID from t_package
    loop {
        // Prevent infinite loops
        if seen_ids.contains(&current_id) {
            break;
        }
        seen_ids.insert(current_id);

        // Get parent package info from t_package table
        let mut stmt =
            conn.prepare("SELECT Name, Parent_ID FROM t_package WHERE Package_ID = ?1")?;

        let result: Result<(String, Option<i64>), _> = stmt.query_row([current_id], |row| {
            let name: String = row.get(0)?;
            let parent_id: Option<i64> = row.get(1)?;
            Ok((name, parent_id))
        });

        match result {
            Ok((_name, Some(parent_id))) => {
                if parent_id != 0 {
                    // Parent exists and is not root (0 means no parent in EA)
                    let mut parent_stmt =
                        conn.prepare("SELECT Name FROM t_package WHERE Package_ID = ?1")?;
                    if let Ok(parent_name) =
                        parent_stmt.query_row([parent_id], |row| row.get::<_, String>(0))
                    {
                        path_parts.insert(0, parent_name);
                        current_id = parent_id;
                    } else {
                        break;
                    }
                } else {
                    // Hit root (Parent_ID = 0)
                    break;
                }
            }
            Ok((_name, None)) => {
                // Hit root (Parent_ID is NULL)
                break;
            }
            Err(_) => {
                // Lookup failed, stop traversal
                break;
            }
        }

        // Safety limit on traversal depth
        if path_parts.len() > 20 {
            break;
        }
    }

    Ok(path_parts.join("::"))
}

fn build_element_hierarchy(
    conn: &Connection,
    element_id: i64,
    element_name: &str,
) -> Result<String> {
    // Query to get the element's package
    let mut stmt = conn.prepare("SELECT PackageID FROM t_object WHERE ObjectID = ?1")?;

    let pkg_id_opt: Option<i64> = stmt
        .query_row([element_id], |row| {
            // PackageID might be NULL, so return Option
            match row.get(0) {
                Ok(id) => Ok(Some(id)),
                Err(rusqlite::Error::InvalidColumnType(_, _, _)) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .ok()
        .flatten();

    // If no package ID, just return element name
    let Some(mut pkg_id) = pkg_id_opt else {
        return Ok(element_name.to_string());
    };

    // Build hierarchy by traversing package parents
    let mut path_parts = vec![element_name.to_string()];
    let mut seen_ids = std::collections::HashSet::new();

    // Traverse up the package hierarchy (with cycle detection)
    loop {
        // Prevent infinite loops
        if seen_ids.contains(&pkg_id) {
            break;
        }
        seen_ids.insert(pkg_id);

        // Get package name and parent
        let mut pkg_stmt = conn.prepare(
            "SELECT Name, PackageID FROM t_object WHERE ObjectID = ?1 AND (SELECT COUNT(*) FROM t_object WHERE ObjectID = ?1 AND Stereotype LIKE '%Package%') > 0"
        )?;

        let pkg_result: Result<(String, Option<i64>), _> = pkg_stmt.query_row([pkg_id], |row| {
            let name: String = row.get(0)?;
            let parent_id: Option<i64> = row.get(1).ok().flatten();
            Ok((name, parent_id))
        });

        match pkg_result {
            Ok((pkg_name, Some(parent_id))) => {
                path_parts.insert(0, pkg_name);
                pkg_id = parent_id;
            }
            Ok((pkg_name, None)) => {
                // Root package
                path_parts.insert(0, pkg_name);
                break;
            }
            Err(_) => {
                // If lookup fails, stop traversal
                break;
            }
        }

        // Safety limit on traversal depth
        if path_parts.len() > 20 {
            break;
        }
    }

    Ok(path_parts.join("::"))
}

/// Extract t_object table, grouping elements by package hierarchy.
///
/// Each package becomes a separate "document" with its fully qualified hierarchical name
/// as the filename. This treats packages as logical file containers, enabling better
/// context for secret discovery within organizational structures.
///
/// Returns vec of `(logical_name, sql_bytes)` where:
/// - logical_name is hierarchical: "Company/IT/Systems_4.sql" for package "Company::IT::Systems" with ObjectID 4
/// - sql_bytes contains CREATE TABLE + INSERT statements for elements in that package
fn extract_t_object_by_packages(
    conn: &Connection,
    remaining_budget: usize,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut result_docs = Vec::new();
    let mut total_bytes = 0;

    // In Enterprise Architect, packages are stored in the t_package table, not t_object.
    // - t_package: Master package list with Package_ID, Name, Parent_ID (hierarchy)
    // - t_object: Elements/objects with Object_ID, Package_ID (FK), Name, Stereotype, Note, etc.
    // All objects have a Package_ID pointing to their containing package.

    // Get all packages from t_package table (the actual package master list)
    let mut stmt =
        conn.prepare("SELECT Package_ID, Name, Parent_ID FROM t_package ORDER BY Package_ID")?;

    let packages: Vec<(i64, String, Option<i64>)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;

    debug!("extract_t_object_by_packages: Found {} packages in t_package table", packages.len());

    // For each package, create a separate document
    for (pkg_id, pkg_name, _parent_id) in packages {
        if total_bytes >= remaining_budget {
            break;
        }

        // Build the fully qualified hierarchical name by traversing t_package Parent_ID chain
        match build_package_hierarchy(conn, pkg_id, &pkg_name) {
            Ok(hierarchy_name) => {
                match extract_package_contents(
                    conn,
                    pkg_id,
                    &pkg_name,
                    remaining_budget - total_bytes,
                ) {
                    Ok((pkg_sql, size)) => {
                        if size > 0 {
                            // Convert hierarchy format: "Company::IT::Systems" -> "Company/IT/Systems_4.sql"
                            // Include Package_ID to ensure uniqueness across packages with similar names
                            let filename =
                                format!("{}_{}.sql", hierarchy_name.replace("::", "/"), pkg_id);
                            result_docs.push((filename, pkg_sql.into_bytes()));
                            total_bytes += size;
                        }
                    }
                    Err(e) => {
                        debug!("Failed to extract package {} contents: {e:#}", hierarchy_name);
                    }
                }
            }
            Err(e) => {
                debug!("Failed to build hierarchy for package {}: {e:#}", pkg_name);
            }
        }
    }

    // Also handle root-level elements (elements with no package)
    if total_bytes < remaining_budget {
        match extract_root_elements(conn, remaining_budget - total_bytes) {
            Ok((root_sql, size)) => {
                if size > 0 {
                    result_docs.push(("__root_package__.sql".to_string(), root_sql.into_bytes()));
                }
            }
            Err(e) => {
                debug!("Failed to extract root elements: {e:#}");
            }
        }
    }

    Ok(result_docs)
}

/// Extract all elements that belong to a specific package.
fn extract_package_contents(
    conn: &Connection,
    package_id: i64,
    package_name: &str,
    remaining_budget: usize,
) -> Result<(String, usize)> {
    let mut out = String::with_capacity(4096);

    // CREATE TABLE statement
    let create_sql = "CREATE TABLE t_object (ObjectID INTEGER PRIMARY KEY, Name TEXT, Stereotype TEXT, Notes TEXT, Package_ID INTEGER);\n";
    out.push_str(create_sql);

    // Get the package's hierarchical name to add as context
    let package_hierarchy = build_package_hierarchy(conn, package_id, package_name)
        .unwrap_or_else(|_| package_name.to_string());

    let header_comment = format!("-- PACKAGE HIERARCHY: {}\n", package_hierarchy);
    out.push_str(&header_comment);

    // Query: all elements that have this package as their parent
    let mut stmt = conn.prepare(
        "SELECT ObjectID, Name, Stereotype, Notes, Package_ID FROM t_object WHERE Package_ID = ?1 ORDER BY ObjectID"
    )?;

    let mut rows = stmt.query([package_id])?;

    while let Some(row) = rows.next()? {
        if out.len() >= remaining_budget {
            break;
        }

        let obj_id: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        let stereotype: Option<String> = row.get(2)?;
        let notes: Option<String> = row.get(3)?;
        let _parent_id: Option<i64> = row.get(4)?;

        // Add hierarchy comment for context
        if let Ok(elem_hierarchy) = build_element_hierarchy(conn, obj_id, &name) {
            let comment = format!("-- HIERARCHY: {}\n", elem_hierarchy);
            out.push_str(&comment);
        }

        // Build INSERT statement
        let name_esc = name.replace('\'', "''");
        let stereotype_val = stereotype
            .as_ref()
            .map(|s| format!("'{}'", s.replace('\'', "''")))
            .unwrap_or_else(|| "NULL".to_string());
        let notes_val = notes
            .as_ref()
            .map(|n| format!("'{}'", n.replace('\'', "''")))
            .unwrap_or_else(|| "NULL".to_string());

        let insert_sql = format!(
            "INSERT INTO t_object (ObjectID, Name, Stereotype, Notes, Package_ID) VALUES ({}, '{}', {}, {}, {});\n",
            obj_id, name_esc, stereotype_val, notes_val, package_id
        );
        out.push_str(&insert_sql);
    }

    let size = out.len();
    Ok((out, size))
}

/// Extract root-level elements (those not inside any package).
fn extract_root_elements(conn: &Connection, remaining_budget: usize) -> Result<(String, usize)> {
    let mut out = String::with_capacity(4096);

    let create_sql = "CREATE TABLE t_object (ObjectID INTEGER PRIMARY KEY, Name TEXT, Stereotype TEXT, Notes TEXT, Package_ID INTEGER);\n";
    out.push_str(create_sql);

    // Query: elements with no package that are not themselves packages
    let mut stmt = conn.prepare(
        "SELECT ObjectID, Name, Stereotype, Notes FROM t_object WHERE Package_ID IS NULL AND Stereotype NOT LIKE '%Package%' ORDER BY ObjectID"
    )?;

    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        if out.len() >= remaining_budget {
            break;
        }

        let obj_id: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        let stereotype: Option<String> = row.get(2)?;
        let notes: Option<String> = row.get(3)?;

        let stereotype_val = stereotype
            .as_ref()
            .map(|s| format!("'{}'", s.replace('\'', "''")))
            .unwrap_or_else(|| "NULL".to_string());
        let notes_val = notes
            .as_ref()
            .map(|n| format!("'{}'", n.replace('\'', "''")))
            .unwrap_or_else(|| "NULL".to_string());

        let insert_sql = format!(
            "INSERT INTO t_object (ObjectID, Name, Stereotype, Notes, Package_ID) VALUES ({}, '{}', {}, {}, NULL);\n",
            obj_id,
            name.replace('\'', "''"),
            stereotype_val,
            notes_val
        );
        out.push_str(&insert_sql);
    }

    let size = out.len();
    Ok((out, size))
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
        conn.execute_batch("CREATE TABLE random_table (id INTEGER PRIMARY KEY, data TEXT);")
            .unwrap();
        drop(conn);

        // Should fail with descriptive error
        let result = extract_qeax_contents(&path);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("Enterprise Architect"));
    }

    #[test]
    fn builds_element_hierarchy() {
        let (_tmp, path) = {
            let tmp = NamedTempFile::new().unwrap();
            let path = tmp.path().to_path_buf();
            let conn = Connection::open(&path).unwrap();

            // Create EA schema with package hierarchy: Company -> IT -> Systems -> Database
            conn.execute_batch(
                "CREATE TABLE t_object (
                    ObjectID INTEGER PRIMARY KEY,
                    Name TEXT,
                    Stereotype TEXT,
                    PackageID INTEGER
                );
                INSERT INTO t_object VALUES (1, 'Company', 'Package', NULL);
                INSERT INTO t_object VALUES (2, 'IT', 'Package', 1);
                INSERT INTO t_object VALUES (3, 'Systems', 'Package', 2);
                INSERT INTO t_object VALUES (4, 'DatabaseServer', 'BusinessObject', 3);",
            )
            .unwrap();
            (tmp, path)
        };

        let conn = Connection::open(&path).unwrap();
        let hierarchy = build_element_hierarchy(&conn, 4, "DatabaseServer").unwrap();

        // Should build the full hierarchy path
        assert_eq!(hierarchy, "Company::IT::Systems::DatabaseServer");
    }

    #[test]
    fn hierarchy_handles_no_package() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let conn = Connection::open(&path).unwrap();

        // Create minimal schema with element but no package
        conn.execute_batch(
            "CREATE TABLE t_object (
                ObjectID INTEGER PRIMARY KEY,
                Name TEXT,
                Stereotype TEXT,
                PackageID INTEGER
            );
            INSERT INTO t_object VALUES (1, 'StandaloneElement', NULL, NULL);",
        )
        .unwrap();

        let hierarchy = build_element_hierarchy(&conn, 1, "StandaloneElement").unwrap();

        // Should return just the element name if no package
        assert_eq!(hierarchy, "StandaloneElement");
    }
}
