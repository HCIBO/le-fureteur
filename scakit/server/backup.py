from __future__ import annotations

import base64
import io
import json
import os
import struct
import tarfile
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

from sqlalchemy import insert, select, text

from .. import PRODUCT_NAME, __version__
from ..safeio import safe_relpath
from .config import get_config
from .db import Base, engine, init_db

MAGIC = b"LFBK1\n"
CHUNK = 8 * 1024 * 1024


class BackupError(Exception):
    pass


def _key(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


def _encrypt_file(src: Path, dst: Path, passphrase: str) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(16)
    aes = AESGCM(_key(passphrase, salt))
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(MAGIC + salt)
        idx = 0
        while True:
            chunk = fi.read(CHUNK)
            last = len(chunk) < CHUNK
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, chunk, struct.pack(">Q?", idx, last))
            fo.write(struct.pack(">I", len(ct)) + nonce + ct)
            idx += 1
            if last:
                break


def _decrypt_file(src: Path, dst: Path, passphrase: str) -> None:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        if fi.read(len(MAGIC)) != MAGIC:
            raise BackupError("Şifreli yedek biçimi tanınmadı")
        aes = AESGCM(_key(passphrase, fi.read(16)))
        idx, done = 0, False
        while not done:
            hdr = fi.read(4)
            if len(hdr) < 4:
                raise BackupError("Yedek dosyası eksik (kesilmiş olabilir)")
            n = struct.unpack(">I", hdr)[0]
            nonce, ct = fi.read(12), fi.read(n)
            try:
                try:
                    pt = aes.decrypt(nonce, ct, struct.pack(">Q?", idx, False))
                except InvalidTag:
                    pt = aes.decrypt(nonce, ct, struct.pack(">Q?", idx, True))
                    done = True
            except InvalidTag as ex:
                raise BackupError("Parola yanlış veya yedek dosyası bozulmuş") from ex
            fo.write(pt)
            idx += 1


def is_encrypted(path: Path) -> bool:
    with open(path, "rb") as f:
        return f.read(len(MAGIC)) == MAGIC


def _enc(v):
    if isinstance(v, (datetime, date)):
        return {"__dt__": v.isoformat()}
    if isinstance(v, bytes):
        return {"__b64__": base64.b64encode(v).decode()}
    return v


def _dec(v, col):
    if isinstance(v, dict) and "__dt__" in v:
        dt = datetime.fromisoformat(v["__dt__"])
        return dt
    if isinstance(v, dict) and "__b64__" in v:
        return base64.b64decode(v["__b64__"])
    return v


def _add_bytes(tf: tarfile.TarFile, name: str, data: bytes) -> None:
    ti = tarfile.TarInfo(name)
    ti.size, ti.mtime, ti.mode = len(data), int(datetime.now().timestamp()), 0o600
    tf.addfile(ti, io.BytesIO(data))


def backup(out: Path, passphrase: str | None = None, include_files: bool = True, log=print) -> dict:
    init_db()
    cfg = get_config()
    eng = engine()
    counts = {}
    tmp = Path(tempfile.mkstemp(suffix=".tar.gz", dir=out.parent)[1])
    try:
        with tarfile.open(tmp, "w:gz") as tf, eng.connect() as conn:
            for table in Base.metadata.sorted_tables:
                rows = conn.execute(select(table)).mappings().all()
                counts[table.name] = len(rows)
                body = "\n".join(json.dumps({k: _enc(v) for k, v in r.items()}, ensure_ascii=False) for r in rows)
                _add_bytes(tf, f"db/{table.name}.jsonl", body.encode())
            if include_files:
                key = cfg.data_dir / "secret.key"
                if key.exists():
                    tf.add(key, "files/secret.key", recursive=False)
                for sub in ("targets", "scans"):
                    d = cfg.data_dir / sub
                    if d.exists():
                        tf.add(d, f"files/{sub}", filter=lambda ti: None if ti.issym() or ti.islnk() else ti)
            manifest = {"product": PRODUCT_NAME, "version": __version__, "created_at": datetime.now(timezone.utc).isoformat(),
                        "dialect": eng.dialect.name, "tables": counts, "files": include_files,
                        "secret_from_env": bool(os.environ.get("SCAKIT_SECRET_KEY"))}
            _add_bytes(tf, "manifest.json", json.dumps(manifest, indent=1).encode())
        if passphrase:
            _encrypt_file(tmp, out, passphrase)
        else:
            os.replace(tmp, out)
        out.chmod(0o600)
        log(f"Yedek yazıldı: {out} ({out.stat().st_size // 1024} KB){' — şifreli' if passphrase else ''}")
        return manifest
    finally:
        tmp.unlink(missing_ok=True)


def restore(src: Path, passphrase: str | None = None, force: bool = False, log=print) -> dict:
    init_db()
    cfg = get_config()
    eng = engine()
    work = Path(tempfile.mkdtemp(dir=cfg.data_dir))
    try:
        plain = src
        if is_encrypted(src):
            if not passphrase:
                raise BackupError("Yedek şifreli; parola gerekli")
            plain = work / "backup.tar.gz"
            _decrypt_file(src, plain, passphrase)
        with eng.connect() as conn:
            from .models import User
            if conn.execute(select(User.__table__)).first() is not None and not force:
                raise BackupError("Hedef kurulum boş değil (kullanıcı var). Üzerine yazmak için --force kullanın.")
        with tarfile.open(plain, "r:gz") as tf:
            names = {m.name: m for m in tf.getmembers()}
            if "manifest.json" not in names:
                raise BackupError("Geçerli bir yedek değil (manifest yok)")
            manifest = json.loads(tf.extractfile(names["manifest.json"]).read())
            tables = {t.name: t for t in Base.metadata.sorted_tables}
            with eng.begin() as conn:
                for table in reversed(Base.metadata.sorted_tables):
                    conn.execute(table.delete())
                for name, table in tables.items():
                    m = names.get(f"db/{name}.jsonl")
                    if m is None:
                        continue
                    rows = []
                    for line in tf.extractfile(m).read().decode().splitlines():
                        if line.strip():
                            raw = json.loads(line)
                            rows.append({c.name: _dec(raw.get(c.name), c) for c in table.columns if c.name in raw})
                    for i in range(0, len(rows), 500):
                        conn.execute(insert(table), rows[i:i + 500])
                if eng.dialect.name == "postgresql":
                    for name, table in tables.items():
                        if "id" in table.columns and table.columns["id"].autoincrement is not False:
                            conn.execute(text(f"SELECT setval(pg_get_serial_sequence('{name}', 'id'), "
                                              f"COALESCE((SELECT MAX(id) FROM {name}), 1))"))
            restored_files = 0
            for m in tf.getmembers():
                if not m.name.startswith("files/") or not m.isfile():
                    continue
                rel = safe_relpath(m.name[len("files/"):])
                if rel is None or rel.split("/")[0] not in ("secret.key", "targets", "scans"):
                    continue
                dest = cfg.data_dir / rel
                if not dest.resolve().is_relative_to(cfg.data_dir.resolve()):
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(m) as fsrc, open(dest, "wb") as fdst:
                    while chunk := fsrc.read(1 << 20):
                        fdst.write(chunk)
                os.chmod(dest, 0o600)
                restored_files += 1
        log(f"Geri yüklendi: {sum(manifest['tables'].values())} kayıt, {restored_files} dosya "
            f"(yedek tarihi {manifest['created_at']}, sürüm {manifest['version']})")
        if manifest.get("secret_from_env"):
            log("! Yedek alınırken gizli anahtar ortam değişkenindeydi: aynı SCAKIT_SECRET_KEY değerini kullanın, "
                "aksi halde şifreli ayarlar (NVD anahtarı, Jira token'ı, webhook adresleri) çözülemez.")
        return manifest
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
