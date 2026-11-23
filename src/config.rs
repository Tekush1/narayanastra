/// Options every module receives.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Debug, Default)]
pub struct ScanConfig {
    /// Effective uid is 0.
    pub is_root: bool,
    /// `--full`: run the expensive checks (PID sweep, bind probe, recursive walks,
    /// full package verification).
    pub full: bool,
    /// Trusted path -> sha256 database for integrity checks.
    pub hashdb: Option<String>,
    /// Extra threat feed file.
    pub feed: Option<String>,
}
