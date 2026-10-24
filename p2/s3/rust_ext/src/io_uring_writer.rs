use std::fs::File;
#[cfg(not(feature = "io_uring"))]
use std::os::unix::fs::FileExt;
use std::os::unix::io::FromRawFd;

use md5::Md5;
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use sha2::{Digest, Sha256};

#[cfg(feature = "io_uring")]
use crossbeam_channel::Sender;
#[cfg(feature = "io_uring")]
use futures_util::future::join_all;
#[cfg(feature = "io_uring")]
use std::sync::OnceLock;
#[cfg(feature = "io_uring")]
use tokio::sync::oneshot;

enum WriteBuffer {
    Owned(Vec<u8>),
    Shared(PyBackedBytes),
}

impl AsRef<[u8]> for WriteBuffer {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Shared(bytes) => bytes.as_ref(),
        }
    }
}

// SAFETY: Vec storage is never resized after submission. PyBackedBytes keeps
// its immutable Python bytes (or a private immutable copy of bytearray) alive.
// Both allocations have stable addresses when the wrapper moves. This buffer
// is write-only: never implement IoBufMut for Python-owned immutable bytes.
#[cfg(feature = "io_uring")]
unsafe impl tokio_uring::buf::IoBuf for WriteBuffer {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ref().as_ptr()
    }

    fn bytes_init(&self) -> usize {
        self.as_ref().len()
    }

    fn bytes_total(&self) -> usize {
        self.as_ref().len()
    }
}

struct WriteSpec {
    fd: i32,
    offset: u64,
    data: WriteBuffer,
}

#[cfg(feature = "io_uring")]
struct WriteJob {
    spec: WriteSpec,
    tx: oneshot::Sender<std::io::Result<()>>,
}

#[cfg(feature = "io_uring")]
struct BatchWriteJob {
    specs: Vec<WriteSpec>,
    tx: oneshot::Sender<std::io::Result<()>>,
}

#[cfg(feature = "io_uring")]
enum UringJob {
    Single(WriteJob),
    Batch(BatchWriteJob),
}

#[cfg(feature = "io_uring")]
static URING_WRITER_CHANNEL: OnceLock<Sender<UringJob>> = OnceLock::new();

#[cfg(feature = "io_uring")]
async fn write_spec(spec: WriteSpec) -> std::io::Result<()> {
    let dup_fd = unsafe { libc::dup(spec.fd) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // The tokio-uring file owns and closes only the duplicated descriptor.
    let file = unsafe { File::from_raw_fd(dup_fd) };
    let ufile = tokio_uring::fs::File::from_std(file);
    let (result, _) = ufile.write_all_at(spec.data, spec.offset).await;
    result
}

#[cfg(feature = "io_uring")]
async fn write_batch(specs: Vec<WriteSpec>) -> std::io::Result<()> {
    // Construct every operation before waiting so io_uring can have the whole
    // batch in flight instead of serializing write completion per object.
    for result in join_all(specs.into_iter().map(write_spec)).await {
        result?;
    }
    Ok(())
}

#[cfg(feature = "io_uring")]
fn init_uring_writer() -> Sender<UringJob> {
    let (tx, rx) = crossbeam_channel::unbounded::<UringJob>();
    std::thread::spawn(move || {
        tokio_uring::start(async move {
            while let Ok(job) = rx.recv() {
                match job {
                    UringJob::Single(job) => {
                        let _ = job.tx.send(write_spec(job.spec).await);
                    }
                    UringJob::Batch(job) => {
                        let _ = job.tx.send(write_batch(job.specs).await);
                    }
                }
            }
        });
    });
    tx
}

#[cfg(feature = "io_uring")]
fn submit_uring_job(job: UringJob) -> std::io::Result<()> {
    let channel = URING_WRITER_CHANNEL.get_or_init(init_uring_writer);
    let (tx, rx) = oneshot::channel();
    let job = match job {
        UringJob::Single(job) => UringJob::Single(WriteJob { spec: job.spec, tx }),
        UringJob::Batch(job) => UringJob::Batch(BatchWriteJob { specs: job.specs, tx }),
    };
    channel
        .send(job)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "io_uring writer stopped"))?;
    rx.blocking_recv()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "io_uring writer stopped"))?
}

#[cfg(not(feature = "io_uring"))]
fn fallback_write(spec: WriteSpec) -> std::io::Result<()> {
    let file = unsafe { File::from_raw_fd(spec.fd) };
    let result = file.write_all_at(spec.data.as_ref(), spec.offset);
    std::mem::forget(file); // Do not close the Python-owned descriptor.
    result
}

/// Write one volume block using the long-lived tokio-uring runtime.
#[pyfunction]
pub fn write_block_uring(
    py: Python<'_>,
    fd: i32,
    offset: u64,
    data: &[u8],
) -> PyResult<(String, String)> {
    let data_vec = data.to_vec();

    py.allow_threads(move || {
        let md5_hex = hex::encode(Md5::digest(&data_vec));
        let sha256_hex = hex::encode(Sha256::digest(&data_vec));
        let spec = WriteSpec { fd, offset, data: WriteBuffer::Owned(data_vec) };

        #[cfg(feature = "io_uring")]
        submit_uring_job(UringJob::Single(WriteJob {
            spec,
            tx: oneshot::channel().0,
        }))
        .map_err(pyo3::exceptions::PyOSError::new_err)?;

        #[cfg(not(feature = "io_uring"))]
        fallback_write(spec).map_err(pyo3::exceptions::PyOSError::new_err)?;

        Ok((md5_hex, sha256_hex))
    })
}

/// Submit a list of volume writes concurrently through one tokio-uring batch.
/// Each item is ``(fd, offset, data)``; the function returns after all writes
/// have completed, or raises the first I/O error.
#[pyfunction]
pub fn write_blocks_uring(
    py: Python<'_>,
    jobs: Vec<(i32, u64, Vec<u8>)>,
) -> PyResult<()> {
    py.allow_threads(move || {
        let specs: Vec<WriteSpec> = jobs
            .into_iter()
            .map(|(fd, offset, data)| WriteSpec { fd, offset, data: WriteBuffer::Owned(data) })
            .collect();
        if specs.is_empty() {
            return Ok(());
        }

        #[cfg(feature = "io_uring")]
        submit_uring_job(UringJob::Batch(BatchWriteJob {
            specs,
            tx: oneshot::channel().0,
        }))
        .map_err(pyo3::exceptions::PyOSError::new_err)?;

        #[cfg(not(feature = "io_uring"))]
        for spec in specs {
            fallback_write(spec).map_err(pyo3::exceptions::PyOSError::new_err)?;
        }

        Ok(())
    })
}

/// Retain immutable Python payload buffers through completion, without making
/// a Rust Vec copy while holding the GIL. The blocking wait releases the GIL.
#[pyfunction]
pub fn write_blocks_shared(
    py: Python<'_>,
    jobs: Vec<(i32, u64, PyBackedBytes)>,
) -> PyResult<()> {
    let specs: Vec<WriteSpec> = jobs
        .into_iter()
        .map(|(fd, offset, data)| WriteSpec { fd, offset, data: WriteBuffer::Shared(data) })
        .collect();
    py.allow_threads(move || {
        if specs.is_empty() {
            return Ok(());
        }
        #[cfg(feature = "io_uring")]
        submit_uring_job(UringJob::Batch(BatchWriteJob {
            specs,
            tx: oneshot::channel().0,
        }))
        .map_err(pyo3::exceptions::PyOSError::new_err)?;

        #[cfg(not(feature = "io_uring"))]
        for spec in specs {
            fallback_write(spec).map_err(pyo3::exceptions::PyOSError::new_err)?;
        }
        Ok(())
    })
}

/// Call fdatasync on a file descriptor.
#[pyfunction]
pub fn fdatasync_uring(py: Python<'_>, fd: i32) -> PyResult<()> {
    py.allow_threads(move || {
        let result = unsafe { libc::fdatasync(fd) };
        if result == 0 {
            Ok(())
        } else {
            Err(pyo3::exceptions::PyOSError::new_err(std::io::Error::last_os_error()))
        }
    })
}
