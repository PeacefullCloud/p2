use std::os::unix::fs::FileExt;
use std::fs::File;
use std::os::unix::io::{FromRawFd, AsRawFd};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[cfg(feature = "io_uring")]
use std::sync::OnceLock;
#[cfg(feature = "io_uring")]
use tokio::sync::oneshot;
#[cfg(feature = "io_uring")]
use crossbeam_channel::Sender;

#[cfg(feature = "io_uring")]
struct ReadJob {
    fd: i32,
    offset: u64,
    length: usize,
    tx: oneshot::Sender<std::io::Result<Vec<u8>>>,
}

#[cfg(feature = "io_uring")]
static URING_READER_CHANNEL: OnceLock<Sender<ReadJob>> = OnceLock::new();

#[cfg(feature = "io_uring")]
fn init_uring_reader() -> Sender<ReadJob> {
    let (tx, rx) = crossbeam_channel::unbounded::<ReadJob>();
    std::thread::spawn(move || {
        tokio_uring::start(async move {
            while let Ok(job) = rx.recv() {
                let dup_fd = unsafe { libc::dup(job.fd) };
                if dup_fd < 0 {
                    let _ = job.tx.send(Err(std::io::Error::last_os_error()));
                    continue;
                }
                let file = unsafe { File::from_raw_fd(dup_fd) };
                let ufile = tokio_uring::fs::File::from_std(file);
                
                let buf = vec![0u8; job.length];
                let (res, buf) = ufile.read_at(buf, job.offset).await;
                
                let result = res.map(|bytes_read| {
                    let mut b = buf;
                    b.truncate(bytes_read);
                    b
                });

                let _ = job.tx.send(result);
            }
        });
    });
    tx
}

/// Read block from a file descriptor using io_uring or fallback to pread.
#[pyfunction]
pub fn read_block_uring<'py>(
    py: Python<'py>,
    fd: i32,
    offset: u64,
    length: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = py.allow_threads(move || {
        #[cfg(feature = "io_uring")]
        {
            let chan = URING_READER_CHANNEL.get_or_init(init_uring_reader);
            let (tx, rx) = oneshot::channel();
            let job = ReadJob {
                fd,
                offset,
                length,
                tx,
            };
            if chan.send(job).is_ok() {
                match rx.blocking_recv() {
                    Ok(Ok(data)) => return Ok(data),
                    Ok(Err(e)) => return Err(pyo3::exceptions::PyOSError::new_err(e)),
                    Err(_) => {}
                }
            }
        }

        // Fallback using standard pread
        let file = unsafe { File::from_raw_fd(fd) };
        let mut buf = vec![0u8; length];
        let res = file.read_at(&mut buf, offset);
        std::mem::forget(file); // Keep original fd open!

        match res {
            Ok(bytes_read) => {
                buf.truncate(bytes_read);
                Ok(buf)
            }
            Err(e) => Err(pyo3::exceptions::PyOSError::new_err(e)),
        }
    })?;

    Ok(PyBytes::new(py, &bytes))
}

#[derive(Clone)]
struct RustBlockCoord {
    vol_uuid: String,
    offset: u64,
    length: u64,
}

#[pyclass]
pub struct RustUringBlockStreamer {
    blocks: Vec<RustBlockCoord>,
    current_block_index: usize,
    current_block_offset: u64,
    vol_dir: String,
    chunk_size: usize,
}

#[pymethods]
impl RustUringBlockStreamer {
    #[new]
    pub fn new(
        blocks_raw: Vec<Bound<'_, pyo3::types::PyDict>>,
        vol_dir: String,
        chunk_size: usize,
    ) -> PyResult<Self> {
        let mut blocks = Vec::new();
        for b in blocks_raw {
            let vol_uuid: String = b.get_item("vol_uuid")?.unwrap().extract()?;
            let offset: u64 = b.get_item("offset")?.unwrap().extract()?;
            let length: u64 = b.get_item("length")?.unwrap().extract()?;
            blocks.push(RustBlockCoord { vol_uuid, offset, length });
        }

        Ok(Self {
            blocks,
            current_block_index: 0,
            current_block_offset: 0,
            vol_dir,
            chunk_size,
        })
    }

    pub fn next_chunk<'py>(&mut self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        if self.current_block_index >= self.blocks.len() {
            return Ok(None);
        }

        let chunk_size = self.chunk_size;
        let vol_dir = self.vol_dir.clone();
        
        // Find how much to read from current block
        let block = &self.blocks[self.current_block_index];
        let block_rem = block.length - self.current_block_offset;
        let to_read = std::cmp::min(chunk_size as u64, block_rem) as usize;

        let vol_path = format!("{}/vol_{}.bin", vol_dir, block.vol_uuid);
        let absolute_offset = block.offset + self.current_block_offset;

        let bytes = py.allow_threads(move || {
            let file = std::fs::OpenOptions::new().read(true).open(&vol_path)?;
            let fd = file.as_raw_fd() as i32;

            #[cfg(feature = "io_uring")]
            {
                let chan = URING_READER_CHANNEL.get_or_init(init_uring_reader);
                let (tx, rx) = oneshot::channel();
                let job = ReadJob {
                    fd,
                    offset: absolute_offset,
                    length: to_read,
                    tx,
                };
                if chan.send(job).is_ok() {
                    if let Ok(Ok(data)) = rx.blocking_recv() {
                        return Ok::<Vec<u8>, std::io::Error>(data);
                    }
                }
            }

            // Fallback pread
            let mut buf = vec![0u8; to_read];
            let bytes_read = file.read_at(&mut buf, absolute_offset)?;
            buf.truncate(bytes_read);
            Ok::<Vec<u8>, std::io::Error>(buf)
        })?;

        // Update offsets
        self.current_block_offset += to_read as u64;
        if self.current_block_offset >= block.length {
            self.current_block_index += 1;
            self.current_block_offset = 0;
        }

        Ok(Some(PyBytes::new(py, &bytes)))
    }
}
