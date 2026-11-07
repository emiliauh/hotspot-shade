use std::process::Command;

#[test]
fn version_reports_the_package_version_and_rejects_extra_arguments() {
    let binary = env!("CARGO_BIN_EXE_hotspotshade");
    let output = Command::new(binary).arg("--version").output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("hotspotshade {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());

    for argument in ["unexpected", "--json"] {
        let extra = Command::new(binary)
            .args(["--version", argument])
            .output()
            .unwrap();
        assert_eq!(extra.status.code(), Some(1));
        assert!(extra.stdout.is_empty());
        assert!(!extra.stderr.is_empty());
    }
}
