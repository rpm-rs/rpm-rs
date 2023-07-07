use std::io;
use std::io::SeekFrom;

pub struct SkipReader<R> {
    reader: R,
    start_pos: u64,
}

impl<R: io::Read + io::Seek> SkipReader<R> {
    pub(crate) fn new(mut reader: R) -> io::Result<Self> {
        let start_pos = reader.stream_position()?;
        Ok(Self { reader, start_pos })
    }
}

impl<R: io::Seek> io::Seek for SkipReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => self.reader.seek(SeekFrom::Start(p + self.start_pos)),
            SeekFrom::Current(p) => self
                .reader
                .seek(SeekFrom::Current(p + self.start_pos as i64)),
            SeekFrom::End(p) => self
                .reader
                .seek(SeekFrom::Current(p + self.start_pos as i64)),
        }
    }
}

impl<R: io::Read> io::Read for SkipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R: io::BufRead> io::BufRead for SkipReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.reader.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.reader.consume(amt)
    }
}
