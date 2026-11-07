//! The source device token environment variable.
//!
//! The CLI accepts the token from `HOTSPOTSHADE_PHONE_TOKEN` for
//! compatibility. A descriptor or a private prompt is preferred. The variable
//! must not stay in the process environment: `/proc/<pid>/environ` and
//! `ps eww` show it, and every child process inherits it. Read it once with
//! [`take_phone_token_env`], then keep `env_remove(PHONE_TOKEN_ENV)` on every
//! child command as a second layer.

/// Name of the environment variable that can carry the source device token.
pub const PHONE_TOKEN_ENV: &str = "HOTSPOTSHADE_PHONE_TOKEN";

/// Read an environment variable and remove it from the process environment.
///
/// Call this only at a single-threaded point, before the process starts a
/// thread or a child. Removing the variable does not erase copies that the
/// caller or the OS already hold. It stops later children from inheriting the
/// value and stops later reads of the process environment from showing it.
pub fn take_env(name: &str) -> Result<String, std::env::VarError> {
    let value = std::env::var(name);
    std::env::remove_var(name);
    value
}

/// Read `HOTSPOTSHADE_PHONE_TOKEN` and remove it from the process environment.
pub fn take_phone_token_env() -> Result<String, std::env::VarError> {
    take_env(PHONE_TOKEN_ENV)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn child_sees(name: &str) -> bool {
        // The shell exits 0 only when the variable is unset, so a zero status
        // means the child did not inherit it.
        !std::process::Command::new("/bin/sh")
            .args(["-c", &format!("test -z \"${{{name}+x}}\"")])
            .status()
            .unwrap()
            .success()
    }

    #[cfg(unix)]
    #[test]
    fn taken_variable_is_not_inherited_by_children() {
        const NAME: &str = "HOTSPOTSHADE_SECRET_ENV_TEST_TAKE";
        std::env::set_var(NAME, "public-test-token");
        assert!(child_sees(NAME));
        assert_eq!(take_env(NAME).unwrap(), "public-test-token");
        assert!(std::env::var_os(NAME).is_none());
        assert!(!child_sees(NAME));
    }

    #[test]
    fn missing_variable_is_an_error_and_stays_missing() {
        const NAME: &str = "HOTSPOTSHADE_SECRET_ENV_TEST_MISSING";
        assert!(take_env(NAME).is_err());
        assert!(std::env::var_os(NAME).is_none());
    }

    #[test]
    fn phone_token_name_is_stable() {
        assert_eq!(PHONE_TOKEN_ENV, "HOTSPOTSHADE_PHONE_TOKEN");
    }
}
