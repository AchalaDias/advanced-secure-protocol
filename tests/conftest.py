import json
import pytest

# --- Fixing modules import path issues ---
import sys, importlib
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))      

try:
    sys.modules.setdefault("protocol", importlib.import_module("server.protocol"))
    sys.modules.setdefault("db", importlib.import_module("server.db"))
except ModuleNotFoundError:
    print("server isn't properly packaged")
    pass
# --------------------------------------------------------

class FakeConn:
    """Socket-like object that records bytes sent."""
    def __init__(self):
        self.sent = bytearray()
        self.closed = False
    def sendall(self, data: bytes):
        assert isinstance(data, (bytes, bytearray)), "handler must send bytes"
        self.sent.extend(data)
    def close(self):
        self.closed = True

@pytest.fixture
def fake_conn():
    return FakeConn()

@pytest.fixture
def aes_key():
    return b"\x11" * 32

@pytest.fixture
def stub_encrypt():
    def _enc(payload, key):
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload, separators=(",", ":"))
        assert isinstance(payload, str)
        return ("ENC[" + payload + "]").encode()
    return _enc

@pytest.fixture
def stub_decrypt():
    def _dec(cipher, key):
        s = cipher.decode(errors="ignore")
        if s.startswith("ENC[") and s.endswith("]"):
            s = s[4:-1]
        return json.loads(s) if s.startswith("{") or s.startswith("[") else s
    return _dec

@pytest.fixture
def H():
    import server.protocol.handler as H
    return H

@pytest.fixture
def patch(monkeypatch, H):
    """Patch helper that targets symbols inside the handler module."""
    def _apply(name, value):
        monkeypatch.setattr(H, name, value, raising=True)
    return _apply
