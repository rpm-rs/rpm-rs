use std::io;

use crate::errors::*;

/// Supported payload compression types.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum CompressionType {
    #[default]
    None,
    Gzip,
    Zstd,
    Xz,
    Bzip2,
}

impl std::fmt::Display for CompressionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Gzip => write!(f, "gzip"),
            Self::Zstd => write!(f, "zstd"),
            Self::Xz => write!(f, "xz"),
            Self::Bzip2 => write!(f, "bzip2"),
        }
    }
}

impl std::str::FromStr for CompressionType {
    type Err = Error;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "gzip" => Ok(CompressionType::Gzip),
            "zstd" => Ok(CompressionType::Zstd),
            "xz" => Ok(CompressionType::Xz),
            "bzip2" => Ok(CompressionType::Bzip2),
            _ => Err(Error::UnknownCompressorType(raw.to_string())),
        }
    }
}

pub enum Compressor {
    None(Vec<u8>),
    #[cfg(feature = "gzip-compression")]
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    /// If the `zstdmt` feature flag is enabled, compression will use all available cores to
    /// compress the file.
    #[cfg(feature = "zstd-compression")]
    Zstd(zstd::stream::Encoder<'static, Vec<u8>>),
    #[cfg(feature = "xz-compression")]
    Xz(xz2::write::XzEncoder<Vec<u8>>),
    #[cfg(feature = "bzip2-compression")]
    Bzip2(bzip2::write::BzEncoder<Vec<u8>>),
}

impl TryFrom<CompressionWithLevel> for Compressor {
    type Error = Error;

    fn try_from(value: CompressionWithLevel) -> Result<Self, Self::Error> {
        match value {
            CompressionWithLevel::None => Ok(Compressor::None(Vec::new())),
            #[cfg(feature = "gzip-compression")]
            CompressionWithLevel::Gzip(level) => Ok(Compressor::Gzip(
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level)),
            )),
            #[cfg(feature = "zstd-compression")]
            CompressionWithLevel::Zstd(level) => {
                #[cfg_attr(not(feature = "zstdmt"), allow(unused_mut))]
                let mut stream = zstd::stream::Encoder::new(Vec::new(), level)?;

                #[cfg(feature = "zstdmt")]
                {
                    let threads = std::thread::available_parallelism()?;
                    // If someone has more than 2^32 threads, I'm impressed
                    stream.multithread(threads.get() as u32)?;
                }

                Ok(Compressor::Zstd(stream))
            }
            #[cfg(feature = "xz-compression")]
            CompressionWithLevel::Xz(level) => Ok(Compressor::Xz(xz2::write::XzEncoder::new(
                Vec::new(),
                level,
            ))),
            #[cfg(feature = "bzip2-compression")]
            CompressionWithLevel::Bzip2(level) => Ok(Compressor::Bzip2(
                bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(level)),
            )),
            // This is an issue when building with all compression types enabled
            #[allow(unreachable_patterns)]
            _ => Err(Error::UnsupportedCompressorType(value.to_string())),
        }
    }
}

impl io::Write for Compressor {
    fn write(&mut self, content: &[u8]) -> Result<usize, std::io::Error> {
        match self {
            Compressor::None(data) => data.write(content),
            #[cfg(feature = "gzip-compression")]
            Compressor::Gzip(encoder) => encoder.write(content),
            #[cfg(feature = "zstd-compression")]
            Compressor::Zstd(encoder) => encoder.write(content),
            #[cfg(feature = "xz-compression")]
            Compressor::Xz(encoder) => encoder.write(content),
            #[cfg(feature = "bzip2-compression")]
            Compressor::Bzip2(encoder) => encoder.write(content),
        }
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        match self {
            Compressor::None(data) => data.flush(),
            #[cfg(feature = "gzip-compression")]
            Compressor::Gzip(encoder) => encoder.flush(),
            #[cfg(feature = "zstd-compression")]
            Compressor::Zstd(encoder) => encoder.flush(),
            #[cfg(feature = "xz-compression")]
            Compressor::Xz(encoder) => encoder.flush(),
            #[cfg(feature = "bzip2-compression")]
            Compressor::Bzip2(encoder) => encoder.flush(),
        }
    }
}

impl Compressor {
    pub(crate) fn finish_compression(self) -> Result<Vec<u8>, Error> {
        match self {
            Compressor::None(data) => Ok(data),
            #[cfg(feature = "gzip-compression")]
            Compressor::Gzip(encoder) => Ok(encoder.finish()?),
            #[cfg(feature = "zstd-compression")]
            Compressor::Zstd(encoder) => Ok(encoder.finish()?),
            #[cfg(feature = "xz-compression")]
            Compressor::Xz(encoder) => Ok(encoder.finish()?),
            #[cfg(feature = "bzip2-compression")]
            Compressor::Bzip2(encoder) => Ok(encoder.finish()?),
        }
    }
}

/// Supported compression types, with an associated compression level. This is used for setting
/// a custom compression configuration during RPM building.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionWithLevel {
    None,
    Zstd(i32),
    Gzip(u32),
    Xz(u32),
    Bzip2(u32),
}

impl CompressionWithLevel {
    pub(crate) fn compression_type(&self) -> CompressionType {
        match self {
            Self::None => CompressionType::None,
            Self::Gzip(_) => CompressionType::Gzip,
            Self::Zstd(_) => CompressionType::Zstd,
            Self::Xz(_) => CompressionType::Xz,
            Self::Bzip2(_) => CompressionType::Bzip2,
        }
    }
}

impl Default for CompressionWithLevel {
    // The preference of the default compression type is listed in decending order and dependent on
    // the enabled feature flags.
    // Writing this without allowing unreachable code is possible but not very pretty. It involves
    // checking if the previous features haven't been enabled on each return so this is a
    // reasonable tradeoff.
    #[allow(unreachable_code)]
    fn default() -> Self {
        #[cfg(feature = "zstd-compression")]
        return CompressionType::Zstd.into();

        #[cfg(feature = "gzip-compression")]
        return CompressionType::Gzip.into();

        #[cfg(feature = "xz-compression")]
        return CompressionType::Xz.into();

        CompressionType::None.into()
    }
}

impl From<CompressionType> for CompressionWithLevel {
    fn from(value: CompressionType) -> Self {
        match value {
            CompressionType::None => CompressionWithLevel::None,
            CompressionType::Gzip => CompressionWithLevel::Gzip(9),
            CompressionType::Xz => CompressionWithLevel::Xz(9),
            CompressionType::Zstd => CompressionWithLevel::Zstd(19),
            CompressionType::Bzip2 => CompressionWithLevel::Bzip2(9),
        }
    }
}

impl std::fmt::Display for CompressionWithLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Gzip(level) => write!(f, "gzip, compression level {level}"),
            Self::Zstd(level) => write!(f, "zstd, compression level {level}"),
            Self::Xz(level) => write!(f, "xz, compression level {level}"),
            Self::Bzip2(level) => write!(f, "bzip2, compression level {level}"),
        }
    }
}

pub(crate) fn decompress_stream(
    value: CompressionType,
    reader: impl io::BufRead + 'static,
) -> Result<Box<dyn io::Read>, Error> {
    match value {
        CompressionType::None => Ok(Box::new(reader)),
        #[cfg(feature = "gzip-compression")]
        CompressionType::Gzip => Ok(Box::new(flate2::bufread::GzDecoder::new(reader))),
        #[cfg(feature = "zstd-compression")]
        CompressionType::Zstd => Ok(Box::new(zstd::stream::Decoder::new(reader)?)),
        #[cfg(feature = "xz-compression")]
        CompressionType::Xz => Ok(Box::new(xz2::bufread::XzDecoder::new(reader))),
        #[cfg(feature = "bzip2-compression")]
        CompressionType::Bzip2 => Ok(Box::new(bzip2::bufread::BzDecoder::new(reader))),
        // This is an issue when building with all compression types enabled
        #[allow(unreachable_patterns)]
        _ => Err(Error::UnsupportedCompressorType(value.to_string())),
    }
}
