//! The engine's declared package version and its bounded artifact record.
//!
//! The record is metadata, not proof of source, signature, or runnability. The
//! release audit does not yet consume it, so the strict release gate stays shut.

const RECORD_SIZE: usize = 64;
const VERSION_OFFSET: usize = 10;
const MAX_VERSION_SIZE: usize = 32;

const fn record(version: &str) -> [u8; RECORD_SIZE] {
    let value = version.as_bytes();
    assert!(!value.is_empty() && value.len() <= MAX_VERSION_SIZE);
    assert!(value.len() <= u8::MAX as usize);
    let mut output = [0; RECORD_SIZE];
    let magic = *b"HSSHVER1";
    let mut index = 0;
    while index < magic.len() {
        output[index] = magic[index];
        index += 1;
    }
    output[8] = 1;
    output[9] = value.len() as u8;
    let mut dots = 0;
    let mut previous_dot = true;
    index = 0;
    while index < value.len() {
        let byte = value[index];
        if byte == b'.' {
            assert!(!previous_dot);
            dots += 1;
            previous_dot = true;
        } else {
            assert!(byte >= b'0' && byte <= b'9');
            previous_dot = false;
        }
        output[VERSION_OFFSET + index] = byte;
        index += 1;
    }
    assert!(dots == 2 && !previous_dot);
    output
}

// The CLI reads this same static so the linker has a live reference even when
// dead stripping is enabled. Non-macOS builds keep it in ordinary data.
#[used]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__TEXT,__hsver"))]
static RECORD: [u8; RECORD_SIZE] = record(env!("CARGO_PKG_VERSION"));

pub fn text() -> &'static str {
    let bytes = std::hint::black_box(&RECORD);
    let length = usize::from(bytes[9]);
    std::str::from_utf8(&bytes[VERSION_OFFSET..VERSION_OFFSET + length])
        .expect("the version record is checked at compile time")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_contains_the_package_version_and_zero_padding() {
        let bytes = &RECORD;
        assert_eq!(&bytes[..8], b"HSSHVER1");
        assert_eq!(bytes[8], 1);
        assert_eq!(text(), env!("CARGO_PKG_VERSION"));
        assert!(bytes[VERSION_OFFSET + usize::from(bytes[9])..]
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn record_rejects_versions_outside_its_format() {
        for value in [
            "",
            "1.2",
            "1..2",
            ".1.2",
            "1.2.",
            "1.2.3-beta",
            "1.2.3.4",
            "1.2.\u{e9}",
            "12345678901234567890123456789.1.2",
            "1234567890123456789012345678901.2.3",
        ] {
            assert!(
                std::panic::catch_unwind(|| record(value)).is_err(),
                "{value}"
            );
        }
        let maximum = record("1234567890123456789012345678.1.2");
        assert_eq!(maximum[9], 32);
    }
}
