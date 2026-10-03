use std::collections::HashMap;

use digest::DynDigest;
use sha2::{Sha256, Sha512};
use sha3::Sha3_256;

use crate::errors::Error;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum HashKind {
    Sha256,
    Sha512,
    Sha3_256,
}

impl HashKind {
    fn build(self) -> Box<dyn DynDigest> {
        match self {
            Self::Sha256 => Box::new(Sha256::default()),
            Self::Sha512 => Box::new(Sha512::default()),
            Self::Sha3_256 => Box::new(Sha3_256::default()),
        }
    }
}

/// A wrapper for calculating the checksum of the contents written to it
pub struct ChecksummingWriter<W> {
    writer: W,
    engines: HashMap<HashKind, Box<dyn DynDigest>>,
    bytes_written: usize,
}

impl<W> ChecksummingWriter<W> {
    pub fn new(writer: W, kinds: &[HashKind]) -> Self {
        Self {
            writer,
            engines: kinds
                .iter()
                .map(|&k| (k, k.build()))
                .collect::<HashMap<_, _>>(),
            bytes_written: 0,
        }
    }

    pub fn into_digests(self) -> (HashMap<HashKind, String>, usize) {
        let map = self
            .engines
            .into_iter()
            .map(|(k, e)| (k, hex::encode(e.finalize())))
            .collect();
        (map, self.bytes_written)
    }
}

impl<W: std::io::Write> std::io::Write for ChecksummingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for eng in self.engines.values_mut() {
            eng.update(buf);
        }
        self.bytes_written += buf.len();
        self.writer.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

/// Allowed special characters in RPM package names (matching RPM's ALLOWED_CHARS_NAME).
const ALLOWED_CHARS_NAME: &[u8] = b".-_+%{}";

/// Allowed first characters in RPM package names (matching RPM's ALLOWED_FIRSTCHARS_NAME),
/// in addition to alphanumeric characters.
const ALLOWED_FIRSTCHARS_NAME: &[u8] = b"_%";

/// Allowed special characters in RPM version/release strings (matching RPM's ALLOWED_CHARS_VERREL).
const ALLOWED_CHARS_VERSION_RELEASE: &[u8] = b"._+%{}~^";

/// Reject strings containing ASCII control characters (except tab and newline).
/// These characters cause problems in downstream consumers like XML repository metadata.
pub(crate) fn reject_control_chars(field: &'static str, value: &str) -> Result<(), Error> {
    if value
        .bytes()
        .any(|b| b.is_ascii_control() && b != b'\t' && b != b'\n')
    {
        return Err(Error::InvalidControlChar {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

/// Validate an RPM package name. Names must start with an alphanumeric character, `_`, or `%`,
/// and may only contain alphanumeric characters plus `.-_+%{}`.
pub(crate) fn validate_name(value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidCharacters {
            field: "name",
            value: value.to_string(),
            reason: "must not be empty",
        });
    }
    let first = value.as_bytes()[0];
    if !first.is_ascii_alphanumeric() && !ALLOWED_FIRSTCHARS_NAME.contains(&first) {
        return Err(Error::InvalidCharacters {
            field: "name",
            value: value.to_string(),
            reason: "must start with an alphanumeric character, '_', or '%'",
        });
    }
    if let Some(bad) = value
        .bytes()
        .find(|b| !b.is_ascii_alphanumeric() && !ALLOWED_CHARS_NAME.contains(b))
    {
        return Err(Error::InvalidCharacters {
            field: "name",
            value: value.to_string(),
            reason: if bad.is_ascii_whitespace() {
                "must not contain whitespace"
            } else {
                "contains invalid character (allowed: alphanumeric, '.', '-', '_', '+', '%', '{', '}')"
            },
        });
    }
    Ok(())
}

/// Validate an RPM version or release string. May only contain alphanumeric characters
/// plus `._+%{}~^`.
pub(crate) fn validate_version(field: &'static str, value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidCharacters {
            field,
            value: value.to_string(),
            reason: "must not be empty",
        });
    }
    if value
        .bytes()
        .any(|b| !b.is_ascii_alphanumeric() && !ALLOWED_CHARS_VERSION_RELEASE.contains(&b))
    {
        return Err(Error::InvalidCharacters {
            field,
            value: value.to_string(),
            reason: "contains invalid character (allowed: alphanumeric, '.', '_', '+', '%', '{', '}', '~', '^')",
        });
    }
    Ok(())
}

/// Normalize an RPM file path by collapsing repeated slashes and removing trailing slashes.
///
/// The input must start with `/` or `./` and must not be `/` or `./` alone
/// (callers should validate and reject these before calling this function).
///
/// This is analogous to RPM's `normalize_path()` which uses `std::filesystem::path::lexically_normal()`,
/// but does not resolve `.` or `..` path components.
pub(crate) fn normalize_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    let mut prev_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !prev_slash {
                result.push(ch);
            }
            prev_slash = true;
        } else {
            result.push(ch);
            prev_slash = false;
        }
    }
    // Remove trailing slash. Callers must reject "/" and "./" before calling this.
    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::Error;

    mod normalize_path {
        use super::*;

        /// Already normalized absolute and relative paths are unchanged.
        #[test]
        fn test_normalize_path_already_normalized() {
            assert_eq!(normalize_path("/usr/bin/foo"), "/usr/bin/foo");
            assert_eq!(normalize_path("./usr/bin/foo"), "./usr/bin/foo");
            assert_eq!(normalize_path("/foo"), "/foo");
            assert_eq!(normalize_path("./foo"), "./foo");
        }

        /// Repeated path separators collapse to one slash.
        #[test]
        fn test_normalize_path_collapse_slashes() {
            assert_eq!(normalize_path("//usr//bin//foo"), "/usr/bin/foo");
            assert_eq!(normalize_path(".//usr//bin"), "./usr/bin");
            assert_eq!(normalize_path("/usr///bin////foo"), "/usr/bin/foo");
        }

        /// Trailing slashes are removed without changing the path prefix.
        #[test]
        fn test_normalize_path_strip_trailing_slash() {
            assert_eq!(normalize_path("/usr/bin/"), "/usr/bin");
            assert_eq!(normalize_path("./usr/bin/"), "./usr/bin");
            assert_eq!(normalize_path("/foo/"), "/foo");
            assert_eq!(normalize_path("./foo/"), "./foo");
        }

        /// Repeated and trailing slashes are normalized together.
        #[test]
        fn test_normalize_path_collapse_and_strip() {
            assert_eq!(normalize_path("//usr///bin//foo/"), "/usr/bin/foo");
            assert_eq!(normalize_path(".//etc//"), "./etc");
            assert_eq!(normalize_path("/usr/bin///"), "/usr/bin");
        }
    }

    mod reject_control_chars {
        use super::*;

        /// NUL, escape, and other forbidden control characters are rejected.
        #[test]
        fn test_reject_control_chars() {
            // ASCII control characters should be rejected
            assert!(matches!(
                reject_control_chars("test", "foo\x07bar"),
                Err(Error::InvalidControlChar { .. })
            ));
            assert!(matches!(
                reject_control_chars("test", "foo\x00bar"),
                Err(Error::InvalidControlChar { .. })
            ));
            assert!(matches!(
                reject_control_chars("test", "foo\x1b[0m"),
                Err(Error::InvalidControlChar { .. })
            ));
            // DEL (0x7F) should be rejected
            assert!(matches!(
                reject_control_chars("test", "foo\x7f"),
                Err(Error::InvalidControlChar { .. })
            ));
        }

        /// Tab and newline remain valid where control characters are checked.
        #[test]
        fn test_reject_control_chars_allows_tab_and_newline() {
            assert!(reject_control_chars("test", "line1\nline2\ttabbed").is_ok());
        }

        /// Plain text and empty strings pass control-character validation.
        #[test]
        fn test_reject_control_chars_allows_normal_text() {
            assert!(reject_control_chars("test", "hello world").is_ok());
            assert!(reject_control_chars("test", "").is_ok());
        }
    }

    mod validate_name {
        use super::*;

        /// Supported package-name punctuation and macros pass validation.
        #[test]
        fn test_validate_name_valid() {
            assert!(validate_name("foo").is_ok());
            assert!(validate_name("foo-bar").is_ok());
            assert!(validate_name("foo_bar").is_ok());
            assert!(validate_name("foo.bar").is_ok());
            assert!(validate_name("foo+bar").is_ok());
            assert!(validate_name("_foo").is_ok());
            assert!(validate_name("%{name}").is_ok());
        }

        /// Package names must not be empty.
        #[test]
        fn test_validate_name_empty() {
            assert!(matches!(
                validate_name(""),
                Err(Error::InvalidCharacters { .. })
            ));
        }

        /// Package names cannot start with a hyphen.
        #[test]
        fn test_validate_name_invalid_first_char() {
            assert!(matches!(
                validate_name("-foo"),
                Err(Error::InvalidCharacters { .. })
            ));
        }

        /// Package names reject spaces and unsupported punctuation.
        #[test]
        fn test_validate_name_invalid_chars() {
            assert!(matches!(
                validate_name("foo bar"),
                Err(Error::InvalidCharacters { .. })
            ));
            assert!(matches!(
                validate_name("foo@bar"),
                Err(Error::InvalidCharacters { .. })
            ));
        }
    }

    mod validate_version {
        use super::*;

        /// Version validation accepts ordinary versions and RPM ordering syntax.
        #[test]
        fn test_validate_version_valid() {
            assert!(validate_version("version", "1.0.0").is_ok());
            assert!(validate_version("version", "1.0.0~rc1").is_ok());
            assert!(validate_version("version", "1.0.0^post1").is_ok());
            assert!(validate_version("version", "1.0+git123").is_ok());
        }

        /// Version strings must not be empty.
        #[test]
        fn test_validate_version_empty() {
            assert!(matches!(
                validate_version("version", ""),
                Err(Error::InvalidCharacters { .. })
            ));
        }

        /// Version strings reject spaces and hyphens.
        #[test]
        fn test_validate_version_invalid_chars() {
            // Hyphen not allowed in version (allowed in name)
            assert!(matches!(
                validate_version("version", "1.0-beta"),
                Err(Error::InvalidCharacters { .. })
            ));
            assert!(matches!(
                validate_version("version", "1.0 0"),
                Err(Error::InvalidCharacters { .. })
            ));
        }

        /// Release validation rejects hyphens as part of the release value.
        #[test]
        fn test_validate_version_release() {
            assert!(matches!(
                validate_version("release", "1-beta"),
                Err(Error::InvalidCharacters { .. })
            ));
        }
    }

    mod checksumming_writer {
        use super::*;
        use std::io::Write;

        /// An empty writer produces the expected digests and byte count.
        #[test]
        fn test_checksumming_writer_empty() {
            let mut buf: Vec<u8> = Vec::new();
            let writer = ChecksummingWriter::new(
                &mut buf,
                &[HashKind::Sha256, HashKind::Sha512, HashKind::Sha3_256],
            );
            let (hash_values, len) = writer.into_digests();
            assert!(buf.is_empty());
            for kind in [HashKind::Sha256, HashKind::Sha512, HashKind::Sha3_256] {
                if let Some(digest) = hash_values.get(&kind) {
                    match kind {
                        HashKind::Sha256 => assert_eq!(
                            digest,
                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        ),
                        HashKind::Sha512 => assert_eq!(
                            digest,
                            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                        ),
                        HashKind::Sha3_256 => assert_eq!(
                            digest,
                            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                        ),
                    }
                }
            }
            assert_eq!(len, 0);
        }

        /// Written bytes contribute to each digest and the recorded length.
        #[test]
        fn test_checksumming_writer_with_data() {
            let mut buf: Vec<u8> = Vec::new();
            let mut writer = ChecksummingWriter::new(
                &mut buf,
                &[HashKind::Sha256, HashKind::Sha512, HashKind::Sha3_256],
            );
            writer.write_all(b"hello world!").unwrap();
            let (hash_values, len) = writer.into_digests();
            assert_eq!(buf.as_slice(), b"hello world!");
            for kind in [HashKind::Sha256, HashKind::Sha512, HashKind::Sha3_256] {
                if let Some(digest) = hash_values.get(&kind) {
                    match kind {
                        HashKind::Sha256 => assert_eq!(
                            digest,
                            "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9"
                        ),
                        HashKind::Sha512 => assert_eq!(
                            digest,
                            "db9b1cd3262dee37756a09b9064973589847caa8e53d31a9d142ea2701b1b28abd97838bb9a27068ba305dc8d04a45a1fcf079de54d607666996b3cc54f6b67c"
                        ),
                        HashKind::Sha3_256 => assert_eq!(
                            digest,
                            "9c24b06143c07224c897bac972e6e92b46cf18063f1a469ebe2f7a0966306105",
                        ),
                    }
                }
            }
            assert_eq!(len, b"hello world!".len());
        }

        /// A writer that performs short writes, returning at most `max_bytes` per call.
        struct ShortWriter<W> {
            inner: W,
            max_bytes: usize,
        }

        impl<W: Write> Write for ShortWriter<W> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let n = buf.len().min(self.max_bytes);
                self.inner.write(&buf[..n])
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.inner.flush()
            }
        }

        /// Short inner writes still hash every byte written by `write_all`.
        #[test]
        fn test_checksumming_writer_short_writes() {
            let data = b"hello world!";

            // Reference: digest without ChecksummingWriter
            let mut ref_buf: Vec<u8> = Vec::new();
            let mut ref_writer = ChecksummingWriter::new(&mut ref_buf, &[HashKind::Sha256]);
            ref_writer.write_all(data).unwrap();
            let (ref_digests, _) = ref_writer.into_digests();
            let expected = ref_digests.get(&HashKind::Sha256).unwrap().clone();

            // Test: wrap a short-writing inner writer (max 3 bytes per write)
            let mut buf: Vec<u8> = Vec::new();
            let short = ShortWriter {
                inner: &mut buf,
                max_bytes: 3,
            };
            let mut writer = ChecksummingWriter::new(short, &[HashKind::Sha256]);
            writer.write_all(data).unwrap();
            let (digests, len) = writer.into_digests();

            assert_eq!(buf.as_slice(), data);
            assert_eq!(len, data.len());
            assert_eq!(digests.get(&HashKind::Sha256).unwrap(), &expected);
        }
    }
}
