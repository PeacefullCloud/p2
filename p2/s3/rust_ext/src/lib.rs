mod crypto;
mod volume_pool;
mod io_uring_writer;
mod io_uring_reader;
mod group_commit;

use pyo3::prelude::*;

#[pymodule]
fn p2_s3_crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Core crypto functions (existing + AES-GCM)
    m.add_function(wrap_pyfunction!(crypto::derive_signing_key, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::hmac_sha256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::hmac_sha256_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::md5_hex, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::md5_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::write_and_hash_small, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::aes_gcm_decrypt, m)?)?;

    // Volume pool allocation class
    m.add_class::<volume_pool::VolumePool>()?;

    // io_uring I/O operations
    m.add_function(wrap_pyfunction!(io_uring_writer::write_block_uring, m)?)?;
    m.add_function(wrap_pyfunction!(io_uring_writer::write_blocks_uring, m)?)?;
    m.add_function(wrap_pyfunction!(io_uring_writer::write_blocks_shared, m)?)?;
    m.add_function(wrap_pyfunction!(io_uring_writer::fdatasync_uring, m)?)?;
    m.add_function(wrap_pyfunction!(io_uring_reader::read_block_uring, m)?)?;
    m.add_class::<io_uring_reader::RustUringBlockStreamer>()?;

    // Group Commit Coordinator
    m.add_class::<group_commit::GroupCommitter>()?;

    Ok(())
}
