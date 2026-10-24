"""Single load point for the compiled Rust extensions.

Why this module exists
----------------------
Each caller used to import the extensions itself, and two different spellings
were in use::

    import p2_s3_crypto                     # -> site-packages (maturin install)
    from p2.s3 import p2_s3_crypto          # -> p2/s3/p2_s3_crypto.so (checked-in)

Those resolve to *different files*, so a process could load two independent
copies of the same extension at once. That actually happened: the checked-in
``.so`` was two weeks older than the installed wheel and was missing
``write_blocks_uring``. Only ``volume_writer`` used the top-level spelling, so
only ``volume_writer`` saw the new function -- every other caller silently ran
against the stale build. Because each copy has its own ``OnceLock`` statics,
the process also ended up with two independent io_uring runtime threads that
could never share a registered descriptor table.

Routing every caller through this module means one module object per extension
per process, and one place to control what happens when a load fails.

Failure behaviour
-----------------
Historically each call site swallowed ``ImportError`` and fell back to a pure
Python path, logging at DEBUG. That is how a stale/missing binary went
unnoticed for so long: throughput quietly dropped and nothing said why. Here a
failed load is reported at WARNING, and a build that loads but lacks expected
symbols is reported at ERROR, since that indicates a stale artifact rather than
an absent one.

Set ``P2_REQUIRE_NATIVE=1`` to turn both conditions into a hard startup
failure. Recommended for benchmarking and production, so a silent fallback can
never be mistaken for a real measurement.
"""

from __future__ import annotations

import importlib
import logging
import os

logger = logging.getLogger(__name__)


def _strict() -> bool:
    return os.environ.get("P2_REQUIRE_NATIVE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


# Symbols each extension is expected to export, mirroring the ``#[pymodule]``
# registrations in rust_ext/src/lib.rs and checksum_ext/src/lib.rs. Checked at
# import so a stale binary is reported loudly instead of surfacing later as an
# AttributeError on a hot path (or, worse, as a silent fallback).
_CRYPTO_SURFACE = (
    "derive_signing_key",
    "hmac_sha256_hex",
    "hmac_sha256_bytes",
    "md5_hex",
    "md5_bytes",
    "write_and_hash_small",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "VolumePool",
    "write_block_uring",
    "write_blocks_uring",
    "write_blocks_shared",
    "fdatasync_uring",
    "read_block_uring",
    "RustUringBlockStreamer",
    "GroupCommitter",
)

_CHECKSUM_SURFACE = (
    "compute_crc32",
    "compute_crc32c",
    "compute_sha1",
    "compute_sha256",
    "verify_crc32",
    "verify_crc32c",
    "verify_sha1",
    "verify_sha256",
)


def _load(module_name: str, expected: tuple[str, ...], build_hint: str):
    """Import *module_name* once and verify it exports *expected*.

    Returns the module, or ``None`` when it cannot be loaded and strict mode is
    off. Never returns a module that is missing expected symbols.
    """
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        message = (
            f"Rust extension {module_name!r} could not be imported ({exc}); "
            f"falling back to the pure-Python path, which is substantially "
            f"slower. Build it with: {build_hint}"
        )
        if _strict():
            raise RuntimeError(
                f"P2_REQUIRE_NATIVE is set but {module_name!r} is unavailable: {exc}"
            ) from exc
        logger.warning(message)
        return None

    missing = [name for name in expected if not hasattr(module, name)]
    if missing:
        message = (
            f"Rust extension {module_name!r} loaded from {getattr(module, '__file__', '?')} "
            f"but is missing {len(missing)} expected symbol(s): {', '.join(missing)}. "
            f"This almost always means the binary is stale relative to its Rust "
            f"source. Rebuild it with: {build_hint}"
        )
        if _strict():
            raise RuntimeError(message)
        logger.error(message)
        return None

    logger.debug("Loaded %s from %s", module_name, getattr(module, "__file__", "?"))
    return module


crypto = _load(
    "p2_s3_crypto",
    _CRYPTO_SURFACE,
    "bash p2/s3/rust_ext/build.sh",
)

checksum = _load(
    "p2_s3_checksum",
    _CHECKSUM_SURFACE,
    "bash p2/s3/checksum_ext/build.sh",
)

HAS_CRYPTO = crypto is not None
HAS_CHECKSUM = checksum is not None

__all__ = ["crypto", "checksum", "HAS_CRYPTO", "HAS_CHECKSUM"]
