"""Test bootstrap: isolate DATA_DIR and make `backend` importable."""
import os
import pathlib
import sys
import tempfile

# config.py reads DATA_DIR at import time; use a throwaway dir so importing the
# backend in tests never touches the real /data
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="stegsuite-test-"))

# app/ must be on sys.path so `import backend...` works when running pytest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
