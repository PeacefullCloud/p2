"""Explicit durability control for opt-in PUT experiments, never deployment."""
import os

from p2.s3.tests.rsgi_settings import *  # noqa: F403

# The default stays strict. Only an explicit benchmark flag changes the
# temporary server, never .env or an existing database/environment.
S3_METADATA_LMDB_SYNC = os.environ.get("P2_TEST_METADATA_SYNC", "1") == "1"
S3_METADATA_LMDB_METASYNC = S3_METADATA_LMDB_SYNC
