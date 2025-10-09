use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Error, ErrorKind, Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

pub type FileId = u32;
pub type Offset = u32;

const OFFSET_SIZE: usize = std::mem::size_of::<Offset>();
const BUFFER_SIZE: usize = 8 * 1024;

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Default)]
#[derive(PartialEq, Eq)]
#[derive(PartialOrd, Ord)]
#[derive(Serialize, Deserialize)]
pub struct Pos(pub FileId, pub Offset);

pub struct Reader {
    pos: Pos,
    file: Option<BufReader<File>>,
    arr: [u8; OFFSET_SIZE],
    end: Pos,
    dir: PathBuf,
}

#[derive(Debug)]
pub struct SplitFile {
    start: Pos,
    end: Pos,
    storage_start: Pos,
    dir: PathBuf,
    max_size_per_file: Offset,
}

impl SplitFile {
    pub fn new(dir: PathBuf, max_size_per_file: Offset) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        let (start, end) = Self::validate_and_scan(&dir, max_size_per_file)?;
        Ok(Self {
            start,
            end,
            dir,
            storage_start: start,
            max_size_per_file,
        })
    }

    fn validate_and_scan(dir: &PathBuf, max_size_per_file: Offset) -> io::Result<(Pos, Pos)> {
        let mut ids: Vec<u32> = Vec::new();
        let mut file_sizes: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Non-file entry found in split file dir: {:?}", path),
                ));
            }

            let filename = path
                .file_name()
                .unwrap()
                .to_str()
                .map(|s| s.to_string())
                .ok_or(Error::new(
                    ErrorKind::InvalidData,
                    format!("Invalid filename in split file dir: {:?}", path),
                ))?;

            let id: u32 = filename.parse().map_err(|_| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Invalid filename in split file dir: {:?}", path),
                )
            })?;

            let len = fs::metadata(&path)?.len();

            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Empty file found in split file dir: {:?}", path),
                ));
            }

            if len > max_size_per_file as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "File size exceeds max_size_per_file in split file dir: {:?}",
                        path
                    ),
                ));
            }

            ids.push(id);
            file_sizes.insert(id, len);
        }

        if ids.is_empty() {
            return Ok((Pos::default(), Pos::default()));
        }

        ids.sort_unstable();

        for i in 1..ids.len() {
            if ids[i] != ids[i - 1] + 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "File IDs are not consecutive: expected {}, got {}",
                        ids[i - 1] + 1,
                        ids[i]
                    ),
                ));
            }
        }

        let min_id = ids[0];
        let max_id = ids[ids.len() - 1];
        let max_size = file_sizes[&max_id];

        let start = Pos(min_id, 0);
        let end = Pos(max_id, max_size as Offset);

        Ok((start, end))
    }

    pub fn advance_start(&mut self) -> io::Result<()> {
        if self.start >= self.end {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Start pointer already at or beyond end pointer",
            ));
        }

        let mut file = BufReader::new(File::open(self.dir.join(self.start.0.to_string()))?);
        file.seek(SeekFrom::Start(self.start.1 as u64))?;

        let mut len_bytes = [0u8; OFFSET_SIZE];
        if let Err(e) = file.read_exact(&mut len_bytes) {
            if e.kind() == ErrorKind::UnexpectedEof {
                self.start.0 += 1;
                self.start.1 = 0;
                return Ok(());
            }
            return Err(e);
        }

        let record_len = u32::from_be_bytes(len_bytes) as Offset;
        self.start.1 += OFFSET_SIZE as Offset + record_len;

        if self.start.1 >= self.max_size_per_file {
            self.start.0 += 1;
            self.start.1 = 0;
        }

        Ok(())
    }

    pub fn read(&self, pos: Pos, max_size: usize) -> io::Result<Vec<u8>> {
        debug_assert!(max_size > 0);

        if pos == self.end {
            return Ok(Vec::new());
        }

        if pos > self.end {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Start position {:?} is beyond end position {:?}",
                    pos, self.end
                ),
            ));
        }

        let reader = self.reader(pos)?;
        let mut result = Vec::with_capacity(max_size.min(8 * 1024));
        let mut remaining = max_size;

        for item in reader {
            let data = item?.1;
            let len = data.len();

            if len > remaining {
                if !result.is_empty() {
                    break;
                }

                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("first record (len {}) exceeds max_size {}", len, max_size),
                ));
            }

            result.extend_from_slice(&data);
            remaining -= data.len();
        }

        Ok(result)
    }

    pub fn reader(&self, pos: Pos) -> io::Result<Reader> {
        if pos > self.end {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Start position {:?} is beyond end position {:?}",
                    pos, self.end
                ),
            ));
        }

        if pos < self.start {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Start position {:?} is before start position {:?}",
                    pos, self.start
                ),
            ));
        }

        Reader::new(pos, self.end, self.dir.clone())
    }

    pub fn reader_all(&self) -> io::Result<Reader> {
        self.reader(self.start)
    }

    pub fn start(&self) -> Pos {
        self.start
    }

    pub fn end(&self) -> Pos {
        self.end
    }

    pub fn remove_all(&mut self) -> io::Result<()> {
        self.start = Pos::default();
        self.end = Pos::default();
        self.storage_start = Pos::default();
        fs::remove_dir_all(&self.dir)
    }
}

impl std::io::Write for SplitFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let full_len = OFFSET_SIZE + buf.len();

        if full_len > self.max_size_per_file as usize {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Buffer size exceeds max_size_per_file: {} > {}",
                    full_len, self.max_size_per_file
                ),
            ));
        }

        let full_len = full_len as Offset;

        if self.end.1 + full_len > self.max_size_per_file {
            self.end.0 += 1;
            self.end.1 = 0;
        }

        let mut file = BufWriter::new(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.dir.join(self.end.0.to_string()))?,
        );

        file.write_all(&(buf.len() as u32).to_be_bytes())?;
        file.write_all(buf)?;
        file.flush()?;

        self.end.1 += full_len;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        debug_assert!(self.start >= self.storage_start);

        if self.start == self.storage_start {
            return Ok(());
        }

        for file_id in self.storage_start.0..self.start.0 {
            fs::remove_file(self.dir.join(file_id.to_string()))?;
        }

        let path = self.dir.join(self.start.0.to_string());
        let metadata = fs::metadata(&path)?;
        let file_size = metadata.len() as u32;

        if self.start.1 == 0 {
            return Ok(());
        }

        if self.start.1 == file_size {
            fs::remove_file(path)?;
            return Ok(());
        }

        let new_size = file_size - self.start.1;
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut read_pos = self.start.1 as u64;
        let mut write_pos = 0u64;

        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;

        loop {
            file.seek(SeekFrom::Start(read_pos))?;
            let bytes_read = file.read(&mut buf)?;

            if bytes_read == 0 {
                break;
            }

            file.seek(SeekFrom::Start(write_pos))?;
            file.write_all(&buf[..bytes_read])?;

            read_pos += bytes_read as u64;
            write_pos += bytes_read as u64;
        }

        file.set_len(new_size as u64)?;
        file.sync_all()?;

        self.storage_start = self.start;
        Ok(())
    }
}

impl Reader {
    fn new(start: Pos, end: Pos, dir: PathBuf) -> io::Result<Self> {
        debug_assert!(start <= end);

        if start == end {
            return Ok(Self {
                pos: start,
                file: None,
                arr: [0u8; OFFSET_SIZE],
                end,
                dir,
            });
        }

        let mut file = BufReader::new(File::open(dir.join(start.0.to_string()))?);
        file.seek(SeekFrom::Start(start.1 as u64))?;

        Ok(Self {
            pos: start,
            file: Some(file),
            arr: [0u8; OFFSET_SIZE],
            end,
            dir,
        })
    }
}

impl Iterator for Reader {
    type Item = io::Result<(Pos, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.end {
            return None;
        }

        let file = self.file.as_mut()?;

        if let Err(e) = file.read_exact(&mut self.arr) {
            self.file = None;

            if e.kind() != ErrorKind::UnexpectedEof {
                return Some(Err(e));
            }

            self.pos.0 += 1;
            self.pos.1 = 0;

            match File::open(self.dir.join(self.pos.0.to_string())) {
                Ok(f) => {
                    self.file = Some(BufReader::new(f));
                    return self.next();
                }
                Err(e) => return Some(Err(e)),
            }
        }

        let len = u32::from_be_bytes(self.arr) as usize;
        let mut buf = vec![0u8; len];

        if let Err(e) = file.read_exact(&mut buf) {
            return Some(Err(e));
        }

        let pos = self.pos;
        self.pos.1 += OFFSET_SIZE as u32 + len as u32;

        Some(Ok((pos, buf)))
    }
}

impl Drop for SplitFile {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}
