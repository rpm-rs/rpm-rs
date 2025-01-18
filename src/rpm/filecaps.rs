// ref. https://github.com/cptpcrd/capctl/blob/4b9ec47b48c6d6669c1d52f73831ad1633562a05/src/caps/cap_text.rs#L5
use std::{fmt::Display, str::FromStr};

use crate::Error;

const CAPS: &[&str; 41] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

#[derive(Debug, Clone)]
pub struct FileCaps(String);

impl FileCaps {
    pub fn new(input: String) -> Result<Self, Error> {
        validate_caps_text(&input)?;

        Ok(Self(input))
    }
}

impl Display for FileCaps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for FileCaps {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate_caps_text(s)?;

        Ok(Self(s.to_owned()))
    }
}

fn validate_capset(s: &str) -> Result<(), Error> {
    if s.is_empty() || s.eq_ignore_ascii_case("all") {
        return Ok(());
    }

    for part in s.split(',') {
        if !CAPS.contains(&part.to_uppercase().as_str()) {
            return Err(Error::InvalidFileCaps(format!("Unknown cap {}", &part)));
        }
    }

    Ok(())
}

fn validate_suffix(s: &str) -> Result<(), Error> {
    let mut last_ch = None;
    for ch in s.chars() {
        match ch {
            '=' | '+' | '-' => match last_ch {
                // No "+/-/=" following each other
                Some('=') | Some('+') | Some('-') => {
                    return Err(Error::InvalidFileCaps(
                        "No `+/-/=` following each other".to_owned(),
                    ))
                }
                _ => (),
            },

            'p' | 'i' | 'e' => debug_assert!(last_ch.is_some()),

            _ => {
                return Err(Error::InvalidFileCaps(format!(
                    "Invalid suffix char {}",
                    ch
                )))
            }
        }

        last_ch = Some(ch);
    }

    Ok(())
}

pub fn validate_caps_text(s: &str) -> Result<(), Error> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::InvalidFileCaps("Empty text".to_owned()));
    }

    for part in s.split_whitespace() {
        let index = match part.find(['+', '-', '=']) {
            Some(i) => i,
            None => return Err(Error::InvalidFileCaps("`+/-/=` not found".to_owned())),
        };

        if index == 0 && !s.starts_with('=') {
            // Example: "+eip" or "-eip"
            return Err(Error::InvalidFileCaps(format!(
                "Unexpected first char of `{}`",
                &part
            )));
        }

        validate_capset(&part[..index])?;
        validate_suffix(&part[index..])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_caps_text, validate_capset, validate_suffix};

    #[test]
    fn test_validate_capset() {
        validate_capset("").unwrap();
        validate_capset("all").unwrap();
        validate_capset("ALL").unwrap();
        validate_capset("cap_chown").unwrap();
        validate_capset("CAP_CHOWN").unwrap();
        validate_capset("cap_chown,cap_syslog").unwrap();

        assert_eq!(
            validate_capset("cap_noexist").unwrap_err().to_string(),
            "Unknown cap cap_noexist"
        );
        assert_eq!(
            validate_capset(",").unwrap_err().to_string(),
            "Unknown cap "
        );
    }

    #[test]
    fn test_validate_suffix() {
        validate_suffix("+p").unwrap();
    }

    #[test]
    fn test_validate_caps_text() {
        assert_eq!(
            validate_caps_text("").unwrap_err().to_string(),
            "Empty text"
        );
        assert_eq!(
            validate_caps_text(" ").unwrap_err().to_string(),
            "Empty text"
        );
        assert_eq!(
            validate_caps_text("cap_chown").unwrap_err().to_string(),
            "`+/-/=` not found"
        );
        assert_eq!(
            validate_caps_text("+eip").unwrap_err().to_string(),
            "Unexpected first char of `+eip`"
        );
        assert_eq!(
            validate_caps_text("-eip").unwrap_err().to_string(),
            "Unexpected first char of `-eip`"
        );
        assert_eq!(
            validate_caps_text("cap_chown+-p").unwrap_err().to_string(),
            "No `+/-/=` following each other"
        );
        assert_eq!(
            validate_caps_text("cap_chown=-p").unwrap_err().to_string(),
            "No `+/-/=` following each other"
        );
        assert_eq!(
            validate_caps_text("cap_chown+y").unwrap_err().to_string(),
            "Invalid suffix char y"
        );
        assert_eq!(
            validate_caps_text("cap_noexist+p").unwrap_err().to_string(),
            "Unknown cap cap_noexist"
        );
        validate_caps_text("cap_chown=p").unwrap();
        validate_caps_text("cap_chown+p").unwrap();
        validate_caps_text("cap_chown+ie").unwrap();
        validate_caps_text("=e cap_chown-e").unwrap();
        validate_caps_text("=e").unwrap();
        validate_caps_text("all=e").unwrap();
    }
}
