"""Private SQLite page transactions and an exclusive acquisition lock."""
import os
import sqlite3
import stat
from pathlib import Path

from cops.evidence import EvidenceError, decode_json
from cops.evidence.canonical import canonical


class Checkpoint:
    def __init__(self, directory, *, confirmed_private=False):
        self.db = None
        self.fd = None
        self.directory = Path(directory)
        try:
            if os.name != 'posix' and not confirmed_private:
                raise EvidenceError('private_storage')
            self.directory.mkdir(mode=0o700, parents=False, exist_ok=True)
            self._private(self.directory, directory=True)
            path = self.directory / 'checkpoint.sqlite3'
            if path.exists() or path.is_symlink():
                self._private(path)
            # Keep the acquisition lock separate from SQLite's own file locks.
            lock = self.directory / '.lock'
            if lock.exists() or lock.is_symlink():
                self._private(lock)
            self.fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            if os.name == 'posix':
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
            else:
                raise EvidenceError('private_storage')
            database_fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            os.close(database_fd)
            for suffix in ('-journal', '-wal', '-shm'):
                sidecar = Path(str(path) + suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    self._private(sidecar)
            self.db = sqlite3.connect(path, timeout=0)
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), document BLOB NOT NULL);'
                                  'CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, document BLOB NOT NULL);'
                                  'CREATE TABLE IF NOT EXISTS cursors (hash TEXT PRIMARY KEY);')
        except Exception:
            self.close()
            raise EvidenceError('private_storage') from None

    @staticmethod
    def _private(path, directory=False):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode)):
            raise EvidenceError('private_storage')
        if os.name == 'posix' and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise EvidenceError('private_storage')
        if not directory and info.st_nlink != 1:
            raise EvidenceError('private_storage')

    def load(self):
        row = self.db.execute('SELECT document FROM state WHERE id=1').fetchone()
        return decode_json(row[0], max_bytes=65536) if row else None

    def save(self, state, records=(), cursor_hash=None):
        with self.db:
            for record in records:
                self.db.execute('INSERT INTO records VALUES (?, ?)', (record['record_id'], canonical(record, max_bytes=16777216, max_depth=64)))
            if cursor_hash:
                self.db.execute('INSERT INTO cursors VALUES (?)', (cursor_hash,))
            self.db.execute('INSERT OR REPLACE INTO state VALUES (1, ?)', (canonical(state, max_bytes=65536),))

    def contains(self, record_id):
        return self.db.execute('SELECT 1 FROM records WHERE id=?', (record_id,)).fetchone() is not None

    def seen_cursor(self, cursor_hash):
        return self.db.execute('SELECT 1 FROM cursors WHERE hash=?', (cursor_hash,)).fetchone() is not None

    def export(self):
        result = []
        for record_id, raw in self.db.execute('SELECT id, document FROM records ORDER BY rowid'):
            record = decode_json(raw, max_bytes=16777216, max_depth=64)
            if not isinstance(record, dict) or record.get('record_id') != record_id:
                raise EvidenceError('checkpoint_invalid')
            result.append(record)
        return result

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self): return self
    def __exit__(self, *args): self.close()
