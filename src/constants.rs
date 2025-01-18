//! RPM specific constants
//!
//! These constants were extracted from the rpm upstream project C headers.

use std::fmt::Display;

use bitflags::bitflags;

use crate::ScriptletIndexTags;

pub const HEADER_IMAGE: u32 = 61;
pub const HEADER_SIGNATURES: u32 = 62;
pub const HEADER_IMMUTABLE: u32 = 63;
pub const HEADER_REGIONS: u32 = 64;
pub const HEADER_I18NTABLE: u32 = 100;
pub const HEADER_SIGBASE: u32 = 256;
pub const HEADER_TAGBASE: u32 = 1000;
pub const RPMTAG_SIG_BASE: u32 = HEADER_SIGBASE;

#[repr(u32)]
#[derive(
    num_derive::FromPrimitive,
    num_derive::ToPrimitive,
    Debug,
    PartialEq,
    Eq,
    Copy,
    Clone,
    enum_display_derive::Display,
)]
#[allow(non_camel_case_types)]
pub enum IndexTag {
    RPMTAG_HEADERIMAGE = HEADER_IMAGE,
    RPMTAG_HEADERSIGNATURES = HEADER_SIGNATURES,
    RPMTAG_HEADERIMMUTABLE = HEADER_IMMUTABLE,
    RPMTAG_HEADERREGIONS = HEADER_REGIONS,

    RPMTAG_HEADERI18NTABLE = HEADER_I18NTABLE,

    RPMTAG_SIGSIZE = RPMTAG_SIG_BASE,
    RPMTAG_SIGLEMD5_1 = RPMTAG_SIG_BASE + 2,
    RPMTAG_SIGPGP = RPMTAG_SIG_BASE + 3,
    RPMTAG_SIGLEMD5_2 = RPMTAG_SIG_BASE + 4,
    RPMTAG_SIGMD5 = RPMTAG_SIG_BASE + 5,

    RPMTAG_SIGGPG = RPMTAG_SIG_BASE + 6,
    RPMTAG_SIGPGP5 = RPMTAG_SIG_BASE + 7,

    RPMTAG_BADSHA1_1 = RPMTAG_SIG_BASE + 8,
    RPMTAG_BADSHA1_2 = RPMTAG_SIG_BASE + 9,
    RPMTAG_PUBKEYS = RPMTAG_SIG_BASE + 10,
    RPMTAG_DSAHEADER = RPMTAG_SIG_BASE + 11,
    RPMTAG_RSAHEADER = RPMTAG_SIG_BASE + 12,
    RPMTAG_SHA1HEADER = RPMTAG_SIG_BASE + 13,

    RPMTAG_LONGSIGSIZE = RPMTAG_SIG_BASE + 14,
    RPMTAG_LONGARCHIVESIZE = RPMTAG_SIG_BASE + 15,

    RPMTAG_SHA256HEADER = RPMTAG_SIG_BASE + 17,
    RPMTAG_VERITYSIGNATURES = RPMTAG_SIG_BASE + 20,
    RPMTAG_VERITYSIGNATUREALGO = RPMTAG_SIG_BASE + 21,

    RPMTAG_NAME = 1000,
    RPMTAG_VERSION = 1001,
    RPMTAG_RELEASE = 1002,
    RPMTAG_EPOCH = 1003,
    RPMTAG_SUMMARY = 1004,
    RPMTAG_DESCRIPTION = 1005,
    RPMTAG_BUILDTIME = 1006,
    RPMTAG_BUILDHOST = 1007,
    RPMTAG_INSTALLTIME = 1008,
    RPMTAG_SIZE = 1009,
    RPMTAG_DISTRIBUTION = 1010,
    RPMTAG_VENDOR = 1011,
    RPMTAG_GIF = 1012,
    RPMTAG_XPM = 1013,
    RPMTAG_LICENSE = 1014,
    RPMTAG_PACKAGER = 1015,
    RPMTAG_GROUP = 1016,
    RPMTAG_CHANGELOG = 1017,
    RPMTAG_SOURCE = 1018,
    RPMTAG_PATCH = 1019,
    RPMTAG_URL = 1020,
    RPMTAG_OS = 1021,
    RPMTAG_ARCH = 1022,
    RPMTAG_PREIN = 1023,
    RPMTAG_POSTIN = 1024,
    RPMTAG_PREUN = 1025,
    RPMTAG_POSTUN = 1026,
    RPMTAG_OLDFILENAMES = 1027,
    RPMTAG_FILESIZES = 1028,
    RPMTAG_FILESTATES = 1029,
    RPMTAG_FILEMODES = 1030,
    RPMTAG_FILEUIDS = 1031,
    RPMTAG_FILEGIDS = 1032,
    RPMTAG_FILERDEVS = 1033,
    RPMTAG_FILEMTIMES = 1034,
    RPMTAG_FILEDIGESTS = 1035,
    RPMTAG_FILELINKTOS = 1036,
    RPMTAG_FILEFLAGS = 1037,
    RPMTAG_ROOT = 1038,
    RPMTAG_FILEUSERNAME = 1039,
    RPMTAG_FILEGROUPNAME = 1040,
    RPMTAG_EXCLUDE = 1041,
    RPMTAG_EXCLUSIVE = 1042,
    RPMTAG_ICON = 1043,
    RPMTAG_SOURCERPM = 1044,
    RPMTAG_FILEVERIFYFLAGS = 1045,
    RPMTAG_ARCHIVESIZE = 1046,
    RPMTAG_PROVIDENAME = 1047,
    RPMTAG_REQUIREFLAGS = 1048,
    RPMTAG_REQUIRENAME = 1049,
    RPMTAG_REQUIREVERSION = 1050,
    RPMTAG_NOSOURCE = 1051,
    RPMTAG_NOPATCH = 1052,
    RPMTAG_CONFLICTFLAGS = 1053,
    RPMTAG_CONFLICTNAME = 1054,
    RPMTAG_CONFLICTVERSION = 1055,
    RPMTAG_DEFAULTPREFIX = 1056,
    RPMTAG_BUILDROOT = 1057,
    RPMTAG_INSTALLPREFIX = 1058,
    RPMTAG_EXCLUDEARCH = 1059,
    RPMTAG_EXCLUDEOS = 1060,
    RPMTAG_EXCLUSIVEARCH = 1061,
    RPMTAG_EXCLUSIVEOS = 1062,
    RPMTAG_AUTOREQPROV = 1063,
    RPMTAG_RPMVERSION = 1064,
    RPMTAG_TRIGGERSCRIPTS = 1065,
    RPMTAG_TRIGGERNAME = 1066,
    RPMTAG_TRIGGERVERSION = 1067,
    RPMTAG_TRIGGERFLAGS = 1068,
    RPMTAG_TRIGGERINDEX = 1069,
    RPMTAG_VERIFYSCRIPT = 1079,
    RPMTAG_CHANGELOGTIME = 1080,
    RPMTAG_CHANGELOGNAME = 1081,
    RPMTAG_CHANGELOGTEXT = 1082,
    RPMTAG_BROKENMD5 = 1083,
    RPMTAG_PREREQ = 1084,
    RPMTAG_PREINPROG = 1085,
    RPMTAG_POSTINPROG = 1086,
    RPMTAG_PREUNPROG = 1087,
    RPMTAG_POSTUNPROG = 1088,
    RPMTAG_BUILDARCHS = 1089,
    RPMTAG_OBSOLETENAME = 1090,
    RPMTAG_VERIFYSCRIPTPROG = 1091,
    RPMTAG_TRIGGERSCRIPTPROG = 1092,
    RPMTAG_DOCDIR = 1093,
    RPMTAG_COOKIE = 1094,
    RPMTAG_FILEDEVICES = 1095,
    RPMTAG_FILEINODES = 1096,
    RPMTAG_FILELANGS = 1097,
    RPMTAG_PREFIXES = 1098,
    RPMTAG_INSTPREFIXES = 1099,
    RPMTAG_TRIGGERIN = 1100,
    RPMTAG_TRIGGERUN = 1101,
    RPMTAG_TRIGGERPOSTUN = 1102,
    RPMTAG_AUTOREQ = 1103,
    RPMTAG_AUTOPROV = 1104,
    RPMTAG_CAPABILITY = 1105,
    RPMTAG_SOURCEPACKAGE = 1106,
    RPMTAG_OLDORIGFILENAMES = 1107,
    RPMTAG_BUILDPREREQ = 1108,
    RPMTAG_BUILDREQUIRES = 1109,
    RPMTAG_BUILDCONFLICTS = 1110,
    RPMTAG_BUILDMACROS = 1111,
    RPMTAG_PROVIDEFLAGS = 1112,
    RPMTAG_PROVIDEVERSION = 1113,
    RPMTAG_OBSOLETEFLAGS = 1114,
    RPMTAG_OBSOLETEVERSION = 1115,
    RPMTAG_DIRINDEXES = 1116,
    RPMTAG_BASENAMES = 1117,
    RPMTAG_DIRNAMES = 1118,
    RPMTAG_ORIGDIRINDEXES = 1119,
    RPMTAG_ORIGBASENAMES = 1120,
    RPMTAG_ORIGDIRNAMES = 1121,
    RPMTAG_OPTFLAGS = 1122,
    RPMTAG_DISTURL = 1123,
    RPMTAG_PAYLOADFORMAT = 1124,
    RPMTAG_PAYLOADCOMPRESSOR = 1125,
    RPMTAG_PAYLOADFLAGS = 1126,
    RPMTAG_INSTALLCOLOR = 1127,
    RPMTAG_INSTALLTID = 1128,
    RPMTAG_REMOVETID = 1129,
    RPMTAG_SHA1RHN = 1130,
    RPMTAG_RHNPLATFORM = 1131,
    RPMTAG_PLATFORM = 1132,
    RPMTAG_PATCHESNAME = 1133,
    RPMTAG_PATCHESFLAGS = 1134,
    RPMTAG_PATCHESVERSION = 1135,
    RPMTAG_CACHECTIME = 1136,
    RPMTAG_CACHEPKGPATH = 1137,
    RPMTAG_CACHEPKGSIZE = 1138,
    RPMTAG_CACHEPKGMTIME = 1139,
    RPMTAG_FILECOLORS = 1140,
    RPMTAG_FILECLASS = 1141,
    RPMTAG_CLASSDICT = 1142,
    RPMTAG_FILEDEPENDSX = 1143,
    RPMTAG_FILEDEPENDSN = 1144,
    RPMTAG_DEPENDSDICT = 1145,
    RPMTAG_SOURCEPKGID = 1146,
    RPMTAG_FILECONTEXTS = 1147,
    RPMTAG_FSCONTEXTS = 1148,
    RPMTAG_RECONTEXTS = 1149,
    RPMTAG_POLICIES = 1150,
    RPMTAG_PRETRANS = 1151,
    RPMTAG_POSTTRANS = 1152,
    RPMTAG_PRETRANSPROG = 1153,
    RPMTAG_POSTTRANSPROG = 1154,
    RPMTAG_DISTTAG = 1155,
    RPMTAG_OLDSUGGESTSNAME = 1156,
    RPMTAG_OLDSUGGESTSVERSION = 1157,
    RPMTAG_OLDSUGGESTSFLAGS = 1158,
    RPMTAG_OLDENHANCESNAME = 1159,
    RPMTAG_OLDENHANCESVERSION = 1160,
    RPMTAG_OLDENHANCESFLAGS = 1161,
    RPMTAG_PRIORITY = 1162,
    RPMTAG_CVSID = 1163,
    RPMTAG_BLINKPKGID = 1164,
    RPMTAG_BLINKHDRID = 1165,
    RPMTAG_BLINKNEVRA = 1166,
    RPMTAG_FLINKPKGID = 1167,
    RPMTAG_FLINKHDRID = 1168,
    RPMTAG_FLINKNEVRA = 1169,
    RPMTAG_PACKAGEORIGIN = 1170,
    RPMTAG_TRIGGERPREIN = 1171,
    RPMTAG_BUILDSUGGESTS = 1172,
    RPMTAG_BUILDENHANCES = 1173,
    RPMTAG_SCRIPTSTATES = 1174,
    RPMTAG_SCRIPTMETRICS = 1175,
    RPMTAG_BUILDCPUCLOCK = 1176,
    RPMTAG_FILEDIGESTALGOS = 1177,
    RPMTAG_VARIANTS = 1178,
    RPMTAG_XMAJOR = 1179,
    RPMTAG_XMINOR = 1180,
    RPMTAG_REPOTAG = 1181,
    RPMTAG_KEYWORDS = 1182,
    RPMTAG_BUILDPLATFORMS = 1183,
    RPMTAG_PACKAGECOLOR = 1184,
    RPMTAG_PACKAGEPREFCOLOR = 1185,
    RPMTAG_XATTRSDICT = 1186,
    RPMTAG_FILEXATTRSX = 1187,
    RPMTAG_DEPATTRSDICT = 1188,
    RPMTAG_CONFLICTATTRSX = 1189,
    RPMTAG_OBSOLETEATTRSX = 1190,
    RPMTAG_PROVIDEATTRSX = 1191,
    RPMTAG_REQUIREATTRSX = 1192,
    RPMTAG_BUILDPROVIDES = 1193,
    RPMTAG_BUILDOBSOLETES = 1194,
    RPMTAG_DBINSTANCE = 1195,
    RPMTAG_NVRA = 1196,

    RPMTAG_FILENAMES = 5000,
    RPMTAG_FILEPROVIDE = 5001,
    RPMTAG_FILEREQUIRE = 5002,
    RPMTAG_FSNAMES = 5003,
    RPMTAG_FSSIZES = 5004,
    RPMTAG_TRIGGERCONDS = 5005,
    RPMTAG_TRIGGERTYPE = 5006,
    RPMTAG_ORIGFILENAMES = 5007,
    RPMTAG_LONGFILESIZES = 5008,
    RPMTAG_LONGSIZE = 5009,
    RPMTAG_FILECAPS = 5010,
    RPMTAG_FILEDIGESTALGO = 5011,
    RPMTAG_BUGURL = 5012,
    RPMTAG_EVR = 5013,
    RPMTAG_NVR = 5014,
    RPMTAG_NEVR = 5015,
    RPMTAG_NEVRA = 5016,
    RPMTAG_HEADERCOLOR = 5017,
    RPMTAG_VERBOSE = 5018,
    RPMTAG_EPOCHNUM = 5019,
    RPMTAG_PREINFLAGS = 5020,
    RPMTAG_POSTINFLAGS = 5021,
    RPMTAG_PREUNFLAGS = 5022,
    RPMTAG_POSTUNFLAGS = 5023,
    RPMTAG_PRETRANSFLAGS = 5024,
    RPMTAG_POSTTRANSFLAGS = 5025,
    RPMTAG_VERIFYSCRIPTFLAGS = 5026,
    RPMTAG_TRIGGERSCRIPTFLAGS = 5027,
    RPMTAG_COLLECTIONS = 5029,
    RPMTAG_POLICYNAMES = 5030,
    RPMTAG_POLICYTYPES = 5031,
    RPMTAG_POLICYTYPESINDEXES = 5032,
    RPMTAG_POLICYFLAGS = 5033,
    RPMTAG_VCS = 5034,
    RPMTAG_ORDERNAME = 5035,
    RPMTAG_ORDERVERSION = 5036,
    RPMTAG_ORDERFLAGS = 5037,
    RPMTAG_MSSFMANIFEST = 5038,
    RPMTAG_MSSFDOMAIN = 5039,
    RPMTAG_INSTFILENAMES = 5040,
    RPMTAG_REQUIRENEVRS = 5041,
    RPMTAG_PROVIDENEVRS = 5042,
    RPMTAG_OBSOLETENEVRS = 5043,
    RPMTAG_CONFLICTNEVRS = 5044,
    RPMTAG_FILENLINKS = 5045,
    RPMTAG_RECOMMENDNAME = 5046,
    RPMTAG_RECOMMENDVERSION = 5047,
    RPMTAG_RECOMMENDFLAGS = 5048,
    RPMTAG_SUGGESTNAME = 5049,
    RPMTAG_SUGGESTVERSION = 5050,
    RPMTAG_SUGGESTFLAGS = 5051,
    RPMTAG_SUPPLEMENTNAME = 5052,
    RPMTAG_SUPPLEMENTVERSION = 5053,
    RPMTAG_SUPPLEMENTFLAGS = 5054,
    RPMTAG_ENHANCENAME = 5055,
    RPMTAG_ENHANCEVERSION = 5056,
    RPMTAG_ENHANCEFLAGS = 5057,
    RPMTAG_RECOMMENDNEVRS = 5058,
    RPMTAG_SUGGESTNEVRS = 5059,
    RPMTAG_SUPPLEMENTNEVRS = 5060,
    RPMTAG_ENHANCENEVRS = 5061,
    RPMTAG_ENCODING = 5062,
    RPMTAG_FILETRIGGERIN = 5063,
    RPMTAG_FILETRIGGERUN = 5064,
    RPMTAG_FILETRIGGERPOSTUN = 5065,
    RPMTAG_FILETRIGGERSCRIPTS = 5066,
    RPMTAG_FILETRIGGERSCRIPTPROG = 5067,
    RPMTAG_FILETRIGGERSCRIPTFLAGS = 5068,
    RPMTAG_FILETRIGGERNAME = 5069,
    RPMTAG_FILETRIGGERINDEX = 5070,
    RPMTAG_FILETRIGGERVERSION = 5071,
    RPMTAG_FILETRIGGERFLAGS = 5072,
    RPMTAG_TRANSFILETRIGGERIN = 5073,
    RPMTAG_TRANSFILETRIGGERUN = 5074,
    RPMTAG_TRANSFILETRIGGERPOSTUN = 5075,
    RPMTAG_TRANSFILETRIGGERSCRIPTS = 5076,
    RPMTAG_TRANSFILETRIGGERSCRIPTPROG = 5077,
    RPMTAG_TRANSFILETRIGGERSCRIPTFLAGS = 5078,
    RPMTAG_TRANSFILETRIGGERNAME = 5079,
    RPMTAG_TRANSFILETRIGGERINDEX = 5080,
    RPMTAG_TRANSFILETRIGGERVERSION = 5081,
    RPMTAG_TRANSFILETRIGGERFLAGS = 5082,
    RPMTAG_REMOVEPATHPOSTFIXES = 5083,
    RPMTAG_FILETRIGGERPRIORITIES = 5084,
    RPMTAG_TRANSFILETRIGGERPRIORITIES = 5085,
    RPMTAG_FILETRIGGERCONDS = 5086,
    RPMTAG_FILETRIGGERTYPE = 5087,
    RPMTAG_TRANSFILETRIGGERCONDS = 5088,
    RPMTAG_TRANSFILETRIGGERTYPE = 5089,
    RPMTAG_FILESIGNATURES = 5090,
    RPMTAG_FILESIGNATURELENGTH = 5091,
    RPMTAG_PAYLOADDIGEST = 5092, // hex-encoded string representing the digest of the payload
    RPMTAG_PAYLOADDIGESTALGO = 5093,
    RPMTAG_AUTOINSTALLED = 5094,
    RPMTAG_IDENTITY = 5095,
    RPMTAG_MODULARITYLABEL = 5096,
    RPMTAG_PAYLOADDIGESTALT = 5097, // hex-encoded string representing the digest of the payload without compression
    RPMTAG_ARCHSUFFIX = 5098,
    RPMTAG_SPEC = 5099,
    RPMTAG_TRANSLATIONURL = 5100,
    RPMTAG_UPSTREAMRELEASES = 5101,
    RPMTAG_SOURCELICENSE = 5102,
    RPMTAG_PREUNTRANS = 5103,
    RPMTAG_POSTUNTRANS = 5104,
    RPMTAG_PREUNTRANSPROG = 5105,
    RPMTAG_POSTUNTRANSPROG = 5106,
    RPMTAG_PREUNTRANSFLAGS = 5107,
    RPMTAG_POSTUNTRANSFLAGS = 5108,
    RPMTAG_SYSUSERS = 5109,
    RPMTAG_BUILDSYSTEM = 5110,
    RPMTAG_BUILDOPTION = 5111,
}

#[repr(u32)]
#[derive(
    num_derive::FromPrimitive,
    num_derive::ToPrimitive,
    Debug,
    PartialEq,
    Eq,
    Copy,
    Clone,
    enum_display_derive::Display,
)]
#[allow(non_camel_case_types)]
pub enum IndexSignatureTag {
    HEADER_SIGNATURES = HEADER_SIGNATURES,
    /// This tag specifies the combined size of the Header and Payload sections.
    RPMSIGTAG_SIZE = HEADER_TAGBASE,

    /// This tag specifies the uncompressed size of the Payload archive, including the cpio headers.
    RPMSIGTAG_PAYLOADSIZE = HEADER_TAGBASE + 7,

    /// The SHA1 checksum of the entire Header Section, including the Header Record, Index Records and
    /// Header store, stored as a hex-encoded string.
    RPMSIGTAG_SHA1 = 269,

    /// This tag specifies the 128-bit MD5 checksum of the combined Header and Archive sections, stored as
    /// a binary representation.
    RPMSIGTAG_MD5 = 1004,

    /// The tag contains the DSA signature of the Header section.
    /// The data is formatted as a Version 3 Signature Packet as specified in RFC 2440: OpenPGP Message Format.
    /// If this tag is present, then the SIGTAG_GPG tag shall also be present.
    RPMSIGTAG_DSA = 267,

    /// The tag contains the RSA signature of the Header section.
    /// The data is formatted as a Version 3 Signature Packet as specified in RFC 2440: OpenPGP Message Format.
    /// If this tag is present, then the SIGTAG_PGP shall also be present.
    RPMSIGTAG_RSA = 268,

    /// Size of combined header and payload if > 4GB.
    RPMSIGTAG_LONGSIZE = 270,

    /// This tag specifies the uncompressed size of the Payload archive, including the cpio headers, when >4gb.
    RPMSIGTAG_LONGARCHIVESIZE = IndexTag::RPMTAG_LONGARCHIVESIZE as u32,

    /// The tag contains the file signature of a file.
    /// The data is formatted as a hex-encoded string.
    /// If this tag is present, then the SIGTAG_FILESIGNATURE_LENGTH shall also be present.
    RPMSIGTAG_FILESIGNATURES = 274,

    /// The tag contains the length of the file signatures in total.
    /// If this tag is present, then the SIGTAG_FILESIGNATURE shall also be present.
    RPMSIGTAG_FILESIGNATURE_LENGTH = 275,

    /// FSVerity signatures of files.
    RPMSIGTAG_VERITYSIGNATURES = IndexTag::RPMTAG_VERITYSIGNATURES as u32,
    /// Algorithm used for FSVerity signatures.
    RPMSIGTAG_VERITYSIGNATUREALGO = IndexTag::RPMTAG_VERITYSIGNATUREALGO as u32,

    /// This tag specifies the RSA signature of the combined Header and Payload sections.
    /// The data is formatted as a Version 3 Signature Packet as specified in RFC 2440: OpenPGP Message Format.
    RPMSIGTAG_PGP = 1002,

    /// The tag contains the DSA signature of the combined Header and Payload sections.
    /// The data is formatted as a Version 3 Signature Packet as specified in RFC 2440: OpenPGP Message Format.
    RPMSIGTAG_GPG = 1005,

    /// This index contains the SHA256 checksum of the entire Header Section, including the Header Record,
    /// Index Records and Header store, stored as a hex-encoded string.
    RPMSIGTAG_SHA256 = IndexTag::RPMTAG_SHA256HEADER as u32,

    /// A silly tag for a date.
    RPMTAG_INSTALLTIME = IndexTag::RPMTAG_INSTALLTIME as u32,
}

/// Header tag.
///
/// Each and every header has a particular header tag that identifies the type of
/// the header the format / information contained in that header.
pub trait Tag: num::FromPrimitive + PartialEq + std::fmt::Display + std::fmt::Debug + Copy {
    fn tag_type_name() -> &'static str;
    fn to_u32(&self) -> u32;
}

impl Tag for IndexTag {
    fn tag_type_name() -> &'static str {
        "IndexTag"
    }

    fn to_u32(&self) -> u32 {
        *self as u32
    }
}

impl Tag for IndexSignatureTag {
    fn tag_type_name() -> &'static str {
        "IndexSignatureTag"
    }

    fn to_u32(&self) -> u32 {
        *self as u32
    }
}

/// Size (in bytes) of the package "lead" section
pub const LEAD_SIZE: u32 = 96;
/// Size (in bytes) of the index header (the fixed portion of each header)
pub const INDEX_HEADER_SIZE: u32 = 16;
/// Size (in bytes) of each entry in the index
pub const INDEX_ENTRY_SIZE: u32 = 16;
/// rpm magic as part of the lead header
pub const RPM_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];

/// header magic recognition (not the lead!)
pub const HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];

bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct DependencyFlags: u32 {
        const ANY = 0;
        const LESS = 1 << 1;
        const GREATER = 1 << 2;
        const EQUAL = 1 << 3;

        const LE = Self::LESS.bits() | Self::EQUAL.bits();
        const GE = Self::GREATER.bits() | Self::EQUAL.bits();

        // bit 4 unused
        const POSTTRANS = 1 << 5;  // %posttrans dependency
        const PREREQ = 1 << 6;     // legacy prereq dependency
        const PRETRANS = 1 << 7;   // pre-transaction dependency
        const INTERP = 1 << 8;     // interpreter used by scriptlet
        const SCRIPT_PRE = 1 << 9;  // %pre dependency
        const SCRIPT_POST = 1 << 10;  // %post dependency
        const SCRIPT_PREUN = 1 << 11;  // %preun dependency
        const SCRIPT_POSTUN = 1 << 12;  // %postun dependency
        const SCRIPT_VERIFY = 1 << 13;  // %verify dependency
        const FIND_REQUIRES = 1 << 14;  // find-requires generated depenency
        const FIND_PROVIDES = 1 << 15;  // find-provides generated dependency
        const TRIGGERIN = 1 << 16;  // %triggerin dependency
        const TRIGGERUN = 1 << 17;  // %triggerun dependency
        const TRIGGERPOSTUN = 1 << 18;  // %triggerpostun dependency
        const MISSINGOK = 1 << 19;  //suggests/enhances hint
        const PREUNTRANS	= 1 << 20;	// %preuntrans dependency
        const POSTUNTRANS = 1 << 21;	// %postuntrans dependency
        // bits 22-23 unused
        const RPMLIB = 1 << 24;	      // rpmlib(feature) dependency.
        const TRIGGERPREIN = 1 << 25;  // %triggerprein dependency
        const KEYRING	= 1 << 26;
        // bit 27 unused
        const CONFIG	= 1 << 28;    // config() dependency
        const META	= 1 << 29;	      // meta dependency
    }
}

bitflags! {
    /// Flags to configure scriptlet execution,
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct ScriptletFlags: u32 {
        /// Macro expansion
        const EXPAND = 1;
        /// Header queryformat expansion
        const QFORMAT = 1 << 1;
        /// Critical for success/failure
        const CRITICAL = 1 << 2;
    }
}

bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct FileVerifyFlags: u32 {
        const NONE 	= 0;
        const MD5 	= 1 << 0;	      // from %verify(md5) - obsolete */
        const FILEDIGEST = 1 << 0;    // from %verify(filedigest) */
        const FILESIZE 	= 1 << 1;     // from %verify(size) */
        const LINKTO 	= 1 << 2;	  // from %verify(link)
        const USER 	= 1 << 3;	      // from %verify(user)
        const GROUP 	= 1 << 4;	  // from %verify(group)
        const MTIME 	= 1 << 5;	  // from %verify(mtime)
        const MODE 	= 1 << 6;	      // from %verify(mode)
        const RDEV 	= 1 << 7;	      // from %verify(rdev)
        const CAPS 	= 1 << 8;	      // from %verify(caps)
        // bits 9-14 unused, reserved for rpmVerifyAttrs
        const CONTEXTS	= 1 << 15;	  // verify: from --nocontexts
        // bits 16-22 used in rpmVerifyFlags
        // bits 23-27 used in rpmQueryFlags
        const READLINKFAIL= 1 << 28;  // readlink failed
        const READFAIL	= 1 << 29;	  // file read failed
        const LSTATFAIL	= 1 << 30;	  // lstat failed
        const LGETFILECONFAIL	= 1 << 31;	// lgetfilecon failed
    }
}

bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct FileFlags: u32 {
        const CONFIG = 1;  // %%config
        const DOC = 1 << 1;  // %%doc
        const DONOTUSE = 1 << 2;  // %%donotuse
        const MISSINGOK = 1 << 3;  // %%config(missingok)
        const NOREPLACE = 1 << 4;  // %%config(noreplace)
        const SPECFILE = 1 << 5; // specfile, which is the first file in a source RPM
        const GHOST = 1 << 6;  // %%ghost
        const LICENSE = 1 << 7;  // %%license
        const README = 1 << 8;  // %%readme
        // bits 9-10 unused
        const PUBKEY = 1 << 11;	// %%pubkey
        const ARTIFACT	= 1 << 12;	// %%artifact
    }
}

// should be equivalent the value mapping used by `pgp::crypto::hash::HashAlgorithm`
// but we have to copy it as not everyone uses the `signature` feature
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, enum_primitive_derive::Primitive)]
pub enum DigestAlgorithm {
    Md5 = 1,
    Sha2_256 = 8,
    Sha2_384 = 9,
    Sha2_512 = 10,
    Sha2_224 = 11,
}

/// Index tag values for the %prein scriptlet,
pub(crate) const PREIN_TAGS: ScriptletIndexTags = (
    IndexTag::RPMTAG_PREIN,
    IndexTag::RPMTAG_PREINFLAGS,
    IndexTag::RPMTAG_PREINPROG,
);

/// Index tag values for the %postin scriptlet,
pub(crate) const POSTIN_TAGS: ScriptletIndexTags = (
    IndexTag::RPMTAG_POSTIN,
    IndexTag::RPMTAG_POSTINFLAGS,
    IndexTag::RPMTAG_POSTINPROG,
);

/// Index tag values for the %preun scriptlet,
pub(crate) const PREUN_TAGS: ScriptletIndexTags = (
    IndexTag::RPMTAG_PREUN,
    IndexTag::RPMTAG_PREUNFLAGS,
    IndexTag::RPMTAG_PREUNPROG,
);

/// Index tag values for the %postun scriptlet,
pub(crate) const POSTUN_TAGS: ScriptletIndexTags = (
    IndexTag::RPMTAG_POSTUN,
    IndexTag::RPMTAG_POSTUNFLAGS,
    IndexTag::RPMTAG_POSTUNPROG,
);

/// Index tag values for the %pretrans scriptlet,
pub(crate) const PRETRANS_TAGS: ScriptletIndexTags = (
    IndexTag::RPMTAG_PRETRANS,
    IndexTag::RPMTAG_PRETRANSFLAGS,
    IndexTag::RPMTAG_PRETRANSPROG,
);

/// Index tag values for the %posttrans scriptlet,
pub(crate) const POSTTRANS_TAGS: ScriptletIndexTags = (
    IndexTag::RPMTAG_POSTTRANS,
    IndexTag::RPMTAG_POSTTRANSFLAGS,
    IndexTag::RPMTAG_POSTTRANSPROG,
);

/// Index tag values for the %preuntrans scriptlet,
pub(crate) const PREUNTRANS_TAGS: ScriptletIndexTags = (
    IndexTag::RPMTAG_PREUNTRANS,
    IndexTag::RPMTAG_PREUNTRANSFLAGS,
    IndexTag::RPMTAG_PREUNTRANSPROG,
);

/// Index tag values for the %postuntrans scriptlet,
pub(crate) const POSTUNTRANS_TAGS: ScriptletIndexTags = (
    IndexTag::RPMTAG_POSTUNTRANS,
    IndexTag::RPMTAG_POSTUNTRANSFLAGS,
    IndexTag::RPMTAG_POSTUNTRANSPROG,
);
