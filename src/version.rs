use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;

/// A full RPM "NEVRA" consists of 5 different components - Name, Epoch, Version, Release, and Architecture.
///
/// Name is the name of the package.
///
/// Epoch overrides all other fields and is generally only used as a last resort - in cases where
/// a change to the versioning scheme or packaging error creates a situation where newer packages
/// might otherwise sort as being older.
///
/// Version is the normal version string used by the upstream project. This shouldn't be tweaked
/// by the packager.
///
/// Release indicates firstly the number of times this package has been released - for instance,
/// with custom patches and backports not present in the upstream, but may also indicate other
/// details such as the OS it was built for (fc38, el9) or portions of a git commit hash.
///
/// Architecture indicates the CPU architecture that this package is intended to support.
///
/// In many contexts (on a system, in a repository), package NEVRAs are meant to be unique. You can have
/// different packages with the same NEVRA - but you can't install both, or put them both in a repo.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Nevra<'a> {
    name: Cow<'a, str>,
    evr: Evr<'a>,
    arch: Cow<'a, str>,
}

impl<'a> Nevra<'a> {
    /// Create a new NEVRA
    pub fn new<T: Into<Cow<'a, str>>>(
        name: T,
        epoch: T,
        version: T,
        release: T,
        arch: T,
    ) -> Nevra<'a> {
        Self {
            name: name.into(),
            evr: Evr::new(epoch, version, release),
            arch: arch.into(),
        }
    }

    /// Create a NEVRA parsed from a string
    pub fn parse(nevra: &'a str) -> Self {
        let (n, e, v, r, a) = Nevra::parse_values(nevra);
        Self::new(n, e, v, r, a)
    }

    /// The name value
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The EVR
    pub fn evr(&'a self) -> &'a Evr<'a> {
        &self.evr
    }

    /// The epoch value
    pub fn epoch(&self) -> &str {
        &self.evr.epoch
    }

    /// The version value
    pub fn version(&self) -> &str {
        &self.evr.version
    }

    /// The release value
    pub fn release(&self) -> &str {
        &self.evr.release
    }

    /// The arch value
    pub fn arch(&self) -> &str {
        &self.arch
    }

    /// Return the epoch, version and release values as a 5-element tuple
    pub fn values(&self) -> (&str, &str, &str, &str, &str) {
        (
            &self.name,
            &self.evr.epoch,
            &self.evr.version,
            &self.evr.release,
            &self.arch,
        )
    }

    /// Parse the name, epoch, version, release and arch values and return them as a 5-element tuple
    pub fn parse_values(nevra: &'a str) -> (&'a str, &'a str, &'a str, &'a str, &'a str) {
        let (name, evra) = nevra.split_once('-').unwrap_or((nevra, ""));
        let (epoch, vra) = evra.split_once(':').unwrap_or(("", evra));
        let (version, ra) = vra.split_once('-').unwrap_or((vra, ""));
        let (release, arch) = ra.rsplit_once('.').unwrap_or((ra, ""));

        (name, epoch, version, release, arch)
    }

    /// Write an NEVRA string in a normalized form which always includes an epoch
    ///
    /// The standard string representation of an EVR will ignore the epoch if not set.  A package
    /// having no epoch value is equivalent to having an epoch of zero. Sometimes it is useful to
    /// write NEVRAs in a form such that equivalent values are represented identically, therefore,
    /// this "normalized" form will always include it.
    pub fn as_normalized_form(&self) -> String {
        format!(
            "{}-{}.{}",
            self.name,
            self.evr.as_normalized_form(),
            self.arch
        )
    }

    /// Write an NVRA string - which doesn't include the "epoch"
    ///
    /// This is the form typically used for RPM filenames.
    pub fn nvra(&self) -> String {
        format!(
            "{}-{}-{}.{}",
            self.name, self.evr.version, self.evr.release, self.arch
        )
    }
}

impl fmt::Display for Nevra<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}.{}", self.name, self.evr, self.arch)
    }
}

impl PartialOrd for Nevra<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Nevra<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        let name_cmp = compare_version_string(&self.name, &other.name);
        if name_cmp != Ordering::Equal {
            return name_cmp;
        }

        let evr_cmp = self.evr.cmp(&other.evr);
        if evr_cmp != Ordering::Equal {
            return evr_cmp;
        }

        compare_version_string(&self.arch, &other.arch)
    }
}

/// A full RPM "version" specifier has 3 different components - Epoch, Version, and Release.
///
/// You are not expected to create these manually, but rather from existing RPMs.
///
/// Epoch overrides all other fields and is generally only used as a last resort - in cases where
/// a change to the versioning scheme or packaging error creates a situation where newer packages
/// might otherwise sort as being older.
///
/// Version is the normal version string used by the upstream project. This shouldn't be tweaked
/// by the packager.
///
/// Release indicates firstly the number of times this package has been released - for instance,
/// with custom patches and backports not present in the upstream, but may also indicate other
/// details such as the OS it was built for (fc38, el9) or portions of a git commit hash.
///
/// Tilde (~) and caret (^) are special values used in particular situations. Including ~ in
/// a version is used for denoting pre-releases and will force it to sort as less than a version
/// without a caret, e.g. 0.5.0 vs 0.5.0~rc1. Including ^ in a version is used for denoting snapshots
/// not directly associated with an upstream release and will force it to sort higher, e.g.
/// 0.5.0 vs 0.5.0^deadbeef
#[derive(Clone, Debug, Default, Eq)]
pub struct Evr<'a> {
    epoch: Cow<'a, str>,
    version: Cow<'a, str>,
    release: Cow<'a, str>,
}

impl<'a> Evr<'a> {
    /// Create a new EVR
    pub fn new<T: Into<Cow<'a, str>>>(epoch: T, version: T, release: T) -> Evr<'a> {
        Evr {
            epoch: epoch.into(),
            version: version.into(),
            release: release.into(),
        }
    }

    /// Create an EVR parsed from a string
    pub fn parse(evr: &'a str) -> Self {
        Evr::parse_values(evr).into()
    }

    /// The epoch value
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// The version value
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The release value
    pub fn release(&self) -> &str {
        &self.release
    }

    /// Write an EVR string in a normalized form which always includes an epoch
    ///
    /// The standard string representation of an EVR will ignore the epoch if not set.  A package
    /// having no epoch value is equivalent to having an epoch of zero. Sometimes it is useful to
    /// write NEVRAs in a form such that equivalent values are represented identically, therefore,
    /// this "normalized" form will always include it.
    pub fn as_normalized_form(&self) -> String {
        let epoch = if self.epoch.is_empty() {
            "0"
        } else {
            self.epoch.as_ref()
        };

        format!("{}:{}-{}", epoch, self.version(), self.release())
    }

    /// Return the epoch, version and release values as a 3-element tuple
    pub fn values(&self) -> (&str, &str, &str) {
        (self.epoch(), self.version(), self.release())
    }

    /// Parse the epoch, version and release values and return them as a 3-element tuple
    pub fn parse_values(evr: &'a str) -> (&'a str, &'a str, &'a str) {
        let (epoch, vr) = evr.split_once(':').unwrap_or(("", evr));
        let (version, release) = vr.split_once('-').unwrap_or((vr, ""));

        (epoch, version, release)
    }
}

impl<'a> From<(&'a str, &'a str, &'a str)> for Evr<'a> {
    fn from(val: (&'a str, &'a str, &'a str)) -> Self {
        Evr::new(val.0, val.1, val.2)
    }
}

impl PartialEq for Evr<'_> {
    fn eq(&self, other: &Self) -> bool {
        ((self.epoch == other.epoch)
            || (self.epoch == "" && other.epoch == "0")
            || (self.epoch == "0" && other.epoch == ""))
            && self.version == other.version
            && self.release == other.release
    }
}

impl fmt::Display for Evr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.epoch.is_empty() {
            write!(f, "{}:", self.epoch)?;
        }

        write!(f, "{}-{}", self.version, self.release)
    }
}

impl PartialOrd for Evr<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Evr<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        let epoch_1 = if self.epoch.is_empty() {
            "0"
        } else {
            &self.epoch
        };
        let epoch_2 = if other.epoch.is_empty() {
            "0"
        } else {
            &other.epoch
        };

        let epoch_cmp = compare_version_string(epoch_1, epoch_2);
        if epoch_cmp != Ordering::Equal {
            return epoch_cmp;
        }

        let version_cmp = compare_version_string(&self.version, &other.version);
        if version_cmp != Ordering::Equal {
            return version_cmp;
        }

        compare_version_string(&self.release, &other.release)
    }
}

/// internal use: each individual component of the EVR is compared using this function
fn compare_version_string(version1: &str, version2: &str) -> Ordering {
    if version1 == version2 {
        return Ordering::Equal;
    }

    let mut version1_part = version1;
    let mut version2_part = version2;

    let not_alphanumeric_tilde_or_caret =
        |c: char| !c.is_ascii_alphanumeric() && c != '~' && c != '^';

    loop {
        // Strip any leading non-alphanumeric, non-tilde, non-caret characters
        version1_part = version1_part.trim_start_matches(not_alphanumeric_tilde_or_caret);
        version2_part = version2_part.trim_start_matches(not_alphanumeric_tilde_or_caret);

        // Tilde separator parses as "older" or lesser version
        match (
            version1_part.strip_prefix('~'),
            version2_part.strip_prefix('~'),
        ) {
            (Some(_), None) => return Ordering::Less,
            (None, Some(_)) => return Ordering::Greater,
            (Some(a), Some(b)) => {
                version1_part = a;
                version2_part = b;
                continue;
            }
            _ => (),
        }

        // if two strings are equal but one is longer, the longer one is considered greater
        // ...unless it ends on a caret, which parses as a lesser version (tilde doesn't have this caveat)
        match (
            version1_part.strip_prefix('^'),
            version2_part.strip_prefix('^'),
        ) {
            (Some(_), None) => match version2_part.is_empty() {
                true => return Ordering::Greater,
                false => return Ordering::Less,
            },
            (None, Some(_)) => match version1_part.is_empty() {
                true => return Ordering::Less,
                false => return Ordering::Greater,
            },
            (Some(a), Some(b)) => {
                version1_part = a;
                version2_part = b;
                continue;
            }
            _ => (),
        }

        if version1_part.is_empty() || version2_part.is_empty() {
            break;
        }

        /// match a contiguous string of characters matching the provided pattern
        /// and return it, along with the rest of the string, if one was found
        fn matching_contiguous<F>(string: &str, pat: F) -> Option<(&str, &str)>
        where
            F: Fn(char) -> bool,
        {
            Some(
                string.split_at(
                    string
                        .find(|c| !pat(c))
                        .or(Some(string.len()))
                        .filter(|&x| x > 0)?,
                ),
            )
        }

        if version1_part.starts_with(|c: char| c.is_ascii_digit()) {
            match (
                matching_contiguous(version1_part, |c| c.is_ascii_digit()),
                matching_contiguous(version2_part, |c| c.is_ascii_digit()),
            ) {
                (Some((prefix1, rest1)), Some((prefix2, rest2))) => {
                    version1_part = rest1;
                    version2_part = rest2;

                    let prefix1 = prefix1.trim_start_matches('0');
                    let prefix2 = prefix2.trim_start_matches('0');

                    let ordering = prefix1.len().cmp(&prefix2.len());
                    if ordering != Ordering::Equal {
                        return ordering;
                    }
                    let ordering = prefix1.cmp(prefix2);
                    if ordering != Ordering::Equal {
                        return ordering;
                    }
                }
                (Some(_), None) => return Ordering::Greater,
                _ => unreachable!(),
            }
        } else {
            match (
                matching_contiguous(version1_part, |c| c.is_ascii_alphabetic()),
                matching_contiguous(version2_part, |c| c.is_ascii_alphabetic()),
            ) {
                (Some((prefix1, rest1)), Some((prefix2, rest2))) => {
                    version1_part = rest1;
                    version2_part = rest2;

                    let ordering = prefix1.cmp(prefix2);
                    if ordering != Ordering::Equal {
                        return ordering;
                    }
                }
                (Some(_), None) => return Ordering::Less,
                _ => unreachable!(),
            }
        }
    }

    version1_part.len().cmp(&version2_part.len())
}

/// Compare two strings as RPM EVR values
pub fn rpm_evr_compare(evr1: &str, evr2: &str) -> Ordering {
    let evr1 = Evr::parse(evr1);
    let evr2 = Evr::parse(evr2);
    evr1.cmp(&evr2)
}

#[cfg(test)]
mod test {
    use super::*;

    /// Test that NEVRAs are printed as expected
    #[test]
    fn test_nevra_tostr() {
        let nevra = Nevra::new("foo", "", "1.2.3", "45", "x86_64");
        assert_eq!("foo-1.2.3-45.x86_64", nevra.to_string());
        assert_eq!("foo-0:1.2.3-45.x86_64", nevra.as_normalized_form());

        let nevra = Nevra::new("foo", "0", "1.2.3", "45", "x86_64");
        assert_eq!("foo-0:1.2.3-45.x86_64", nevra.to_string());
        assert_eq!("foo-0:1.2.3-45.x86_64", nevra.as_normalized_form());

        let nevra = Nevra::new("foo", "1", "2.3.4", "5", "x86_64");
        assert_eq!("foo-1:2.3.4-5.x86_64", nevra.to_string());
        assert_eq!("foo-1:2.3.4-5.x86_64", nevra.as_normalized_form());

        let nevra = Nevra::new("python3.9", "0", "3.9.11", "2.fc38", "x86_64");
        assert_eq!("python3.9-0:3.9.11-2.fc38.x86_64", nevra.to_string());
        assert_eq!(
            "python3.9-0:3.9.11-2.fc38.x86_64",
            nevra.as_normalized_form()
        );
    }

    /// Test that a correctly formed EVR string is parsed correctly
    #[test]
    fn test_nevra_parse() {
        let nevra = Nevra::new("foo", "", "1.2.3", "45", "x86_64");
        assert_eq!(Nevra::parse("foo-1.2.3-45.x86_64"), nevra);

        let nevra = Nevra::new("foo", "0", "1.2.3", "45", "x86_64");
        assert_eq!(Nevra::parse("foo-0:1.2.3-45.x86_64"), nevra);

        let nevra = Nevra::new("foo", "1", "2.3.4", "5", "x86_64");
        assert_eq!(Nevra::parse("foo-1:2.3.4-5.x86_64"), nevra);

        let nevra = Nevra::new("python3.9", "0", "3.9.11", "2", "x86_64");
        assert_eq!(Nevra::parse("python3.9-3.9.11-2.x86_64"), nevra);

        let nevra = Nevra::new("python3.9", "0", "3.9.11", "2.fc38", "x86_64");
        assert_eq!(Nevra::parse("python3.9-3.9.11-2.fc38.x86_64"), nevra);
    }

    /// Test that various not-well-formed NEVRA strings still get parsed in a sensible way
    #[test]
    fn test_nevra_parse_edge_cases() {
        assert_eq!(Nevra::parse_values("foo"), ("foo", "", "", "", ""));
        assert_eq!(Nevra::parse_values("foo-1.2"), ("foo", "", "1.2", "", ""));
        assert_eq!(
            Nevra::parse_values("foo-1.2-3.bar"),
            ("foo", "", "1.2", "3", "bar")
        );
        assert_eq!(
            Nevra::parse_values("foo-1.2-3.bar.x86_64"),
            ("foo", "", "1.2", "3.bar", "x86_64")
        );
        assert_eq!(
            Nevra::parse_values("python3.9-3.9.11-2.fc38.x86_64"),
            ("python3.9", "", "3.9.11", "2.fc38", "x86_64")
        );

        assert_eq!(Evr::parse_values("-"), ("", "", ""));
        assert_eq!(Evr::parse_values("."), ("", ".", ""));
        assert_eq!(Evr::parse_values(":"), ("", "", ""));
        assert_eq!(Evr::parse_values(":-"), ("", "", ""));
        assert_eq!(Evr::parse_values(".-"), ("", ".", ""));
        assert_eq!(Evr::parse_values("0"), ("", "0", ""));
        assert_eq!(Evr::parse_values("0-"), ("", "0", ""));
        assert_eq!(Evr::parse_values(":0"), ("", "0", ""));
        assert_eq!(Evr::parse_values(":0-"), ("", "0", ""));
        assert_eq!(Evr::parse_values("0:"), ("0", "", ""));
        assert_eq!(Evr::parse_values("asdf:"), ("asdf", "", ""));
        assert_eq!(Evr::parse_values("~:"), ("~", "", ""));
    }

    /// Test comparing NEVRAs using comparison operators
    #[test]
    fn test_nevra_ord() {
        let nevra1 = Nevra::parse("foo-1.2.3-45.noarch");
        let nevra2 = Nevra::parse("foo-1.2.3-45.noarch");
        assert!(nevra1 == nevra2);

        let nevra1 = Nevra::parse("foo-1.2.3-45.noarch");
        let nevra2 = Nevra::parse("foo-0:1.2.3-45.noarch");
        assert!(nevra1 == nevra2);

        let nevra1 = Nevra::parse("bar-1.2.3-45.noarch");
        let nevra2 = Nevra::parse("foo-9:1.2.3-45.noarch");
        assert!(nevra1 < nevra2);

        let nevra1 = Nevra::parse("foo-1.2.3-45.noarch");
        let nevra2 = Nevra::parse("foobar-1.2.3-45.noarch");
        assert!(nevra1 < nevra2);

        let nevra1 = Nevra::parse("foo-2.3.4-5.noarch");
        let nevra2 = Nevra::parse("foobar-1.2.3-45.noarch");
        assert!(nevra1 < nevra2);

        let nevra1 = Nevra::parse("bar-1.2.3-45.noarch");
        let nevra2 = Nevra::parse("foo-1.2.3-45.noarch");
        assert!(nevra1 < nevra2);

        let nevra1 = Nevra::parse("foo-1.2.3-45.fc38.noarch");
        let nevra2 = Nevra::parse("foo-1.2.3-45.fc39.noarch");
        assert!(nevra1 < nevra2);

        let nevra1 = Nevra::parse("foo-1.2.3-45.fc39.i386");
        let nevra2 = Nevra::parse("foo-1.2.3-45.fc39.x86_64");
        assert!(nevra1 < nevra2);

        let nevra1 = Nevra::parse("python3.9-3.9.12-2.fc39.i386");
        let nevra2 = Nevra::parse("python3.11-3.11.7-2.fc39.x86_64");
        assert!(nevra1 < nevra2);

        let nevra1 = Nevra::parse("python3.11-3.11.7-2.fc39.x86_64");
        let nevra2 = Nevra::parse("python3.9-3.9.12-2.fc39.x86_64");
        assert!(nevra1 > nevra2);
    }

    /// Test that EVRs are printed as expected
    #[test]
    fn test_evr_tostr() {
        let evr = Evr::new("", "1.2.3", "45");
        assert_eq!("1.2.3-45", evr.to_string());
        assert_eq!("0:1.2.3-45", evr.as_normalized_form());

        let evr = Evr::new("0", "1.2.3", "45");
        assert_eq!("0:1.2.3-45", evr.to_string());
        assert_eq!("0:1.2.3-45", evr.as_normalized_form());
    }

    /// Test that a correctly formed EVR string is parsed correctly
    #[test]
    fn test_evr_parse() {
        let evr = Evr::new("", "1.2.3", "45");
        assert_eq!(Evr::parse("1.2.3-45"), evr);

        let evr = Evr::new("0", "1.2.3", "45");
        assert_eq!(Evr::parse("0:1.2.3-45"), evr);

        let evr = Evr::new("1", "2.3.4", "5");
        assert_eq!(Evr::parse("1:2.3.4-5"), evr);
    }

    /// Test that various not-well-formed EVR strings still get parsed in a sensible way
    #[test]
    fn test_evr_parse_edge_cases() {
        assert_eq!(Evr::parse_values("-"), ("", "", ""));
        assert_eq!(Evr::parse_values("."), ("", ".", ""));
        assert_eq!(Evr::parse_values(":"), ("", "", ""));
        assert_eq!(Evr::parse_values(":-"), ("", "", ""));
        assert_eq!(Evr::parse_values(".-"), ("", ".", ""));
        assert_eq!(Evr::parse_values("0"), ("", "0", ""));
        assert_eq!(Evr::parse_values("0-"), ("", "0", ""));
        assert_eq!(Evr::parse_values(":0"), ("", "0", ""));
        assert_eq!(Evr::parse_values(":0-"), ("", "0", ""));
        assert_eq!(Evr::parse_values("0:"), ("0", "", ""));
        assert_eq!(Evr::parse_values("asdf:"), ("asdf", "", ""));
        assert_eq!(Evr::parse_values("~:"), ("~", "", ""));
    }

    /// Test direct comparison of rpm EVR strings using rpm_evr_compare
    #[test]
    fn test_rpm_evr_compare() {
        assert_eq!(Ordering::Equal, rpm_evr_compare("0:1.2.3-45", "1.2.3-45"));
        assert_eq!(Ordering::Less, rpm_evr_compare("1.2.3-45", "1:1.2.3-45"));
        assert_eq!(Ordering::Greater, rpm_evr_compare("1.2.3-46", "1.2.3-45"));
    }

    /// Test comparing EVRs using comparison operators
    #[test]
    fn test_evr_ord() {
        // compare the same EVR without epoch as equal
        let evr1 = Evr::parse("1.2.3-45");
        let evr2 = Evr::parse("1.2.3-45");
        assert!(evr1 == evr2);

        // compare the same EVR with epoch as equal
        let evr1 = Evr::parse("2:1.2.3-45");
        let evr2 = Evr::parse("2:1.2.3-45");
        assert!(evr1 == evr2);

        // compare the same EVR with zero-epoch as equal to default-epoch
        let evr1 = Evr::parse("1.2.3-45");
        let evr2 = Evr::parse("0:1.2.3-45");
        assert!(evr1 == evr2);

        // compare EVR with higher epoch and same version / release
        let evr1 = Evr::parse("1.2.3-45");
        let evr2 = Evr::parse("1:1.2.3-45");
        assert!(evr1 < evr2);

        // compare EVR with higher epoch taken over EVR with higher version
        let evr1 = Evr::parse("4.2.3-45");
        let evr2 = Evr::parse("1:1.2.3-45");
        assert!(evr1 < evr2);

        // compare EVR with higher version
        let evr1 = Evr::parse("1.2.3-45");
        let evr2 = Evr::parse("1.2.4-45");
        assert!(evr1 < evr2);

        // compare EVR with higher version
        let evr1 = Evr::parse("1.23.3-45");
        let evr2 = Evr::parse("1.2.3-45");
        assert!(evr1 > evr2);

        // compare EVR with higher version
        let evr1 = Evr::parse("12.2.3-45");
        let evr2 = Evr::parse("1.2.3-45");
        assert!(evr1 > evr2);

        // compare EVR with higher version
        let evr1 = Evr::parse("1.2.3-45");
        let evr2 = Evr::parse("1.12.3-45");
        assert!(evr1 < evr2);

        // compare versions with tilde parsing as older
        let evr1 = Evr::parse("~1.2.3-45");
        let evr2 = Evr::parse("1.2.3-45");
        assert!(evr1 < evr2);

        // compare versions with tilde parsing as older
        let evr1 = Evr::parse("~12.2.3-45");
        let evr2 = Evr::parse("1.2.3-45");
        assert!(evr1 < evr2);

        // compare versions with tilde parsing as older
        let evr1 = Evr::parse("~12.2.3-45");
        let evr2 = Evr::parse("~1.2.3-45");
        assert!(evr1 > evr2);

        // compare versions with tilde parsing as older
        let evr1 = Evr::parse("~3:12.2.3-45");
        let evr2 = Evr::parse("0:1.2.3-45");
        assert!(evr1 < evr2);

        // compare release
        let evr1 = Evr::parse("1.2.3-45");
        let evr2 = Evr::parse("1.2.3-46");
        assert!(evr1 < evr2);

        // compare release
        let evr1 = Evr::parse("1.2.3-45.fc39");
        let evr2 = Evr::parse("1.2.3-46.fc38");
        assert!(evr1 < evr2);

        // compare release
        let evr1 = Evr::parse("1.2.3-3");
        let evr2 = Evr::parse("1.2.3-10");
        assert!(evr1 < evr2);

        // compare release
        let evr1 = Evr::parse("1.2.3-3.fc40");
        let evr2 = Evr::parse("1.2.3-10.fc39");
        assert!(evr1 < evr2);
    }

    /// Test many different combinations of version string comparison behavior
    #[test]
    fn test_compare_version_string() {
        assert_eq!(Ordering::Equal, compare_version_string("1.0", "1.0"));
        assert_eq!(Ordering::Less, compare_version_string("1.0", "2.0"));
        assert_eq!(Ordering::Greater, compare_version_string("2.0", "1.0"));

        assert_eq!(Ordering::Equal, compare_version_string("2.0.1", "2.0.1"));
        assert_eq!(Ordering::Less, compare_version_string("2.0", "2.0.1"));
        assert_eq!(Ordering::Greater, compare_version_string("2.0.1", "2.0"));

        assert_eq!(Ordering::Less, compare_version_string("5.0.1", "5.0.1a"));
        assert_eq!(Ordering::Greater, compare_version_string("5.0.1a", "5.0.1"));

        assert_eq!(Ordering::Equal, compare_version_string("5.0.a1", "5.0.a1"));
        assert_eq!(Ordering::Equal, compare_version_string("5.0.1a", "5.0.1a"));
        assert_eq!(Ordering::Less, compare_version_string("5.0.a1", "5.0.a2"));
        assert_eq!(
            Ordering::Greater,
            compare_version_string("5.0.a2", "5.0.a1")
        );

        assert_eq!(Ordering::Less, compare_version_string("10abc", "10.1abc"));
        assert_eq!(
            Ordering::Greater,
            compare_version_string("10.1abc", "10abc")
        );

        assert_eq!(Ordering::Less, compare_version_string("8.0", "8.0.rc1"));
        assert_eq!(Ordering::Greater, compare_version_string("8.0.rc1", "8.0"));

        assert_eq!(Ordering::Greater, compare_version_string("10b2", "10a1"));
        assert_eq!(Ordering::Less, compare_version_string("10a2", "10b2"));

        assert_eq!(Ordering::Less, compare_version_string("6.6p1", "7.5p1"));
        assert_eq!(Ordering::Greater, compare_version_string("7.5p1", "6.6p1"));

        assert_eq!(Ordering::Equal, compare_version_string("6.5p1", "6.5p1"));
        assert_eq!(Ordering::Less, compare_version_string("6.5p1", "6.5p2"));
        assert_eq!(Ordering::Greater, compare_version_string("6.5p2", "6.5p1"));
        assert_eq!(Ordering::Less, compare_version_string("6.5p2", "6.6p1"));
        assert_eq!(Ordering::Greater, compare_version_string("6.6p1", "6.5p2"));

        assert_eq!(Ordering::Equal, compare_version_string("6.5p10", "6.5p10"));
        assert_eq!(Ordering::Less, compare_version_string("6.5p1", "6.5p10"));
        assert_eq!(Ordering::Greater, compare_version_string("6.5p10", "6.5p1"));

        assert_eq!(Ordering::Equal, compare_version_string("abc10", "abc10"));
        assert_eq!(Ordering::Less, compare_version_string("abc10", "abc10.1"));
        assert_eq!(
            Ordering::Greater,
            compare_version_string("abc10.1", "abc10")
        );

        assert_eq!(Ordering::Equal, compare_version_string("abc.4", "abc.4"));
        assert_eq!(Ordering::Less, compare_version_string("abc.4", "8"));
        assert_eq!(Ordering::Greater, compare_version_string("8", "abc.4"));
        assert_eq!(Ordering::Less, compare_version_string("abc.4", "2"));
        assert_eq!(Ordering::Greater, compare_version_string("2", "abc.4"));

        assert_eq!(Ordering::Equal, compare_version_string("1.0aa", "1.0aa"));
        assert_eq!(Ordering::Less, compare_version_string("1.0a", "1.0aa"));
        assert_eq!(Ordering::Greater, compare_version_string("1.0aa", "1.0a"));
    }

    /// test handling of numeric-like values in version strings
    #[test]
    fn test_version_comparison_numeric_handling() {
        assert_eq!(
            Ordering::Equal,
            compare_version_string("10.0001", "10.0001")
        );
        // sequences of leading zeroes are meant to be ignored - it's not *actually* treated like a numeric value
        assert_eq!(Ordering::Equal, compare_version_string("10.0001", "10.1"));
        assert_eq!(Ordering::Equal, compare_version_string("10.1", "10.0001"));
        assert_eq!(Ordering::Less, compare_version_string("10.0001", "10.0039"));
        assert_eq!(
            Ordering::Greater,
            compare_version_string("10.0039", "10.0001")
        );
        // but sequences of zeroes within a numeric segment are not ignored
        assert_eq!(Ordering::Less, compare_version_string("10.1", "10.10001"));
        assert_eq!(
            Ordering::Less,
            compare_version_string("10.1111", "10.10001")
        );
        assert_eq!(
            Ordering::Greater,
            compare_version_string("10.11111", "10.10001")
        );

        assert_eq!(
            Ordering::Equal,
            compare_version_string("20240521", "20240521")
        );
        assert_eq!(
            Ordering::Less,
            compare_version_string("20240521", "20240522")
        );
        assert_eq!(
            Ordering::Greater,
            compare_version_string("20240522", "20240521")
        );
        assert_eq!(
            Ordering::Less,
            compare_version_string("20240521", "202405210")
        );
    }

    /// Test behavior of tilde and caret operators
    #[test]
    fn test_version_comparison_tilde_and_caret() {
        assert_eq!(
            Ordering::Equal,
            compare_version_string("1.0~rc1", "1.0~rc1")
        );
        assert_eq!(Ordering::Less, compare_version_string("1.0~rc1", "1.0"));
        assert_eq!(Ordering::Greater, compare_version_string("1.0", "1.0~rc1"));
        assert_eq!(Ordering::Less, compare_version_string("1.0~rc1", "1.0~rc2"));
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1.0~rc2", "1.0~rc1")
        );
        assert_eq!(
            Ordering::Equal,
            compare_version_string("1.0~rc1~git123", "1.0~rc1~git123")
        );
        assert_eq!(
            Ordering::Less,
            compare_version_string("1.0~rc1~git123", "1.0~rc1")
        );
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1.0~rc1", "1.0~rc1~git123")
        );

        assert_eq!(Ordering::Equal, compare_version_string("1.0^", "1.0^"));
        assert_eq!(Ordering::Less, compare_version_string("1.0", "1.0^"));
        assert_eq!(Ordering::Greater, compare_version_string("1.0^", "1.0"));

        assert_eq!(Ordering::Less, compare_version_string("1.0", "1.0git1^"));
        assert_eq!(
            Ordering::Less,
            compare_version_string("1.0^git1", "1.0^git2")
        );
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1.01", "1.0^git1")
        );
        assert_eq!(
            Ordering::Equal,
            compare_version_string("1.0^20240501", "1.0^20240501")
        );
        assert_eq!(
            Ordering::Less,
            compare_version_string("1.0^20240501", "1.0.1")
        );
        assert_eq!(
            Ordering::Equal,
            compare_version_string("1.0^20240501^git1", "1.0^20240501^git1")
        );
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1.0^20240502", "1.0^20240501^git1")
        );
        assert_eq!(
            Ordering::Equal,
            compare_version_string("1.0~rc1^git1", "1.0~rc1^git1")
        );
        assert_eq!(
            Ordering::Less,
            compare_version_string("1.0~rc1", "1.0~rc1^git1")
        );
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1.0~rc1^git1", "1.0~rc1")
        );
        assert_eq!(
            Ordering::Equal,
            compare_version_string("1.0^git1~pre", "1.0^git1~pre")
        );
        assert_eq!(
            Ordering::Less,
            compare_version_string("1.0^git1~pre", "1.0^git1")
        );
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1.0^git1", "1.0^git1~pre")
        );
    }

    /// Test some version comparison behavior that is a bit non-intuitive
    /// (but needs to be maintained for compatibility)
    #[test]
    fn test_non_intuitive_comparison_behavior() {
        assert_eq!(Ordering::Less, compare_version_string("1e.fc33", "1.fc33"));
        assert_eq!(
            Ordering::Greater,
            compare_version_string("1g.fc33", "1.fc33")
        );
    }

    /// Test handling of non-alphanumeric ascii characters (excluding separators)
    #[test]
    fn test_non_alphanumeric_equivalence() {
        // the existence of sequences of non-alphanumeric characters should not impact the version comparison at all
        assert_eq!(Ordering::Equal, compare_version_string("b", "b"));
        assert_eq!(Ordering::Equal, compare_version_string("b+", "b+"));
        assert_eq!(Ordering::Equal, compare_version_string("b+", "b_"));
        assert_eq!(Ordering::Equal, compare_version_string("b_", "b+"));
        assert_eq!(Ordering::Equal, compare_version_string("+b", "+b"));
        assert_eq!(Ordering::Equal, compare_version_string("+b", "_b"));
        assert_eq!(Ordering::Equal, compare_version_string("_b", "+b"));

        assert_eq!(Ordering::Equal, compare_version_string("+b", "++b"));
        assert_eq!(Ordering::Equal, compare_version_string("+b", "+b+"));

        assert_eq!(Ordering::Equal, compare_version_string("+.", "+_"));
        assert_eq!(Ordering::Equal, compare_version_string("_+", "+."));
        assert_eq!(Ordering::Equal, compare_version_string("+", "."));
        assert_eq!(Ordering::Equal, compare_version_string(",", "+"));

        assert_eq!(Ordering::Equal, compare_version_string("++", "_"));
        assert_eq!(Ordering::Equal, compare_version_string("+", ".."));

        assert_eq!(Ordering::Equal, compare_version_string("4_0", "4_0"));
        assert_eq!(Ordering::Equal, compare_version_string("4_0", "4.0"));
        assert_eq!(Ordering::Equal, compare_version_string("4.0", "4_0"));

        assert_eq!(Ordering::Less, compare_version_string("4.999", "5.0"));
        assert_eq!(Ordering::Less, compare_version_string("4.999.9", "5.0"));
        assert_eq!(Ordering::Greater, compare_version_string("5.0", "4.999_9"));

        // except when it comes to breaking up sequences of alphanumeric characters that do impact the comparison
        assert_eq!(Ordering::Less, compare_version_string("4.999", "4.999.9"));
        assert_eq!(Ordering::Greater, compare_version_string("4.999", "4.99.9"));
    }

    /// Test handling of non-ascii characters
    #[test]
    fn test_non_ascii_character_equivalence() {
        // the existence of sequences of non-ascii characters should not impact the version comparison at all
        assert_eq!(Ordering::Equal, compare_version_string("1.1.Á.1", "1.1.1"));
        assert_eq!(Ordering::Equal, compare_version_string("1.1.Á", "1.1.Á"));
        assert_eq!(Ordering::Equal, compare_version_string("1.1.Á", "1.1.Ê"));
        assert_eq!(Ordering::Equal, compare_version_string("1.1.ÁÁ", "1.1.Á"));
        assert_eq!(Ordering::Equal, compare_version_string("1.1.Á", "1.1.ÊÊ"));

        // except when it comes to breaking up sequences of ascii characters that do impact the comparison
        assert_eq!(Ordering::Less, compare_version_string("1.1Á1", "1.11"));
    }
}
