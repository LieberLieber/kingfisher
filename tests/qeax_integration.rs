/// Integration test for Sparx Enterprise Architect .qeax file scanning
#[cfg(test)]
mod qeax_integration_tests {
    use std::path::PathBuf;

    #[test]
    fn test_qeax_file_detection() {
        // Test that .qeax files are correctly identified
        let qeax_path: PathBuf = "test.qeax".into();
        let other_path: PathBuf = "test.sqlite".into();
        let generic_path: PathBuf = "test.db".into();

        assert!(kingfisher::sqlite::is_qeax_file(&qeax_path));
        assert!(!kingfisher::sqlite::is_qeax_file(&other_path));
        assert!(!kingfisher::sqlite::is_qeax_file(&generic_path));
    }

    #[test]
    fn test_qeax_file_extension_case_insensitive() {
        // Test that .qeax detection is case-insensitive
        let qeax_upper: PathBuf = "test.QEAX".into();
        let qeax_mixed: PathBuf = "test.QeAx".into();

        assert!(kingfisher::sqlite::is_qeax_file(&qeax_upper));
        assert!(kingfisher::sqlite::is_qeax_file(&qeax_mixed));
    }
}
