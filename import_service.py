"""Authenticated, one-time migration of the original N&C Club CRM database.

The archive never enters GitHub, is checked against the prepared source fingerprint,
then imported transactionally into the durable Railway SQLite volume.
"""
import hashlib
import json
import os
import sqlite3
import threading
import zipfile
from pathlib import Path

LOCK = threading.Lock()
MAX_UPLOAD = 62 * 1024 * 1024
MAX_DATABASE = 100 * 1024 * 1024
SOURCE_SHA256 = 'b8b4dff4bd1f500f5080d2e8b7d11c3a1bd8f8b9761349912418dbd811ba3ac0'
EXPECTED = {
    'contacts': 31596,
    'organizations': 3472,
    'source_rows': 59205,
    'aliases': 28262,
    'duplicate_candidates': 1957,
    'merge_log': 19575,
    'import_batches': 20,
}
TABLE_ORDER = ('organizations','contacts','source_rows','aliases','duplicate_candidates','merge_log','import_batches')

class ImportErrorSafe(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(message)

def _copy_database(upload_file: Path, source_file: Path):
    """Extract only the expected SQLite member, never arbitrary ZIP member paths."""
    try:
        with zipfile.ZipFile(upload_file) as archive:
            entries = [x for x in archive.infolist() if x.filename.split('/')[-1] == 'nc_club.sqlite3']
            if len(entries) != 1:
                raise ImportErrorSafe(422,'The original CRM archive must contain one nc_club.sqlite3 file.')
            item = entries[0]
            if item.file_size > MAX_DATABASE or item.file_size < 1024:
                raise ImportErrorSafe(413,'Unexpected source database size.')
            digest = hashlib.sha256()
            expanded = 0
            with archive.open(item) as inp, source_file.open('wb') as out:
                while True:
                    b=inp.read(1024*1024)
                    if not b: break
                    expanded += len(b)
                    if expanded > MAX_DATABASE: raise ImportErrorSafe(413,'Extracted file exceeds size limit.')
                    digest.update(b)
                    out.write(b)
            if digest.hexdigest() != SOURCE_SHA256:
                raise ImportErrorSafe(422,'Backup fingerprint does not match the verified N&C Club source database.')
    except zipfile.BadZipFile:
        raise ImportErrorSafe(422,'File must be the original N&C Club CRM application ZIP.')

def perform_import(handler, db_path: Path, connect, audit, now, session):
    user=session['user']
    if user['role'] != 'Administrator':
        raise ImportErrorSafe(403,'Only an administrator can import the source database.')
    if handler.headers.get('X-CSRF-Token') != session['csrf']:
        raise ImportErrorSafe(403,'Session request token invalid. Sign in again.')
    if handler.headers.get('Content-Type','').split(';')[0] != 'application/octet-stream':
        raise ImportErrorSafe(415,'Binary ZIP file required.')
    try: size=int(handler.headers.get('Content-Length','0'))
    except ValueError: size=0
    if not (1000 <= size <= MAX_UPLOAD):
        raise ImportErrorSafe(413,'ZIP size must be between 1 KB and 62 MB.')
    if not LOCK.acquire(blocking=False):
        raise ImportErrorSafe(409,'Another import is already in progress.')
    try:
        folder=db_path.parent
        folder.mkdir(parents=True,exist_ok=True)
        upload=folder/'.pending-nc-club-upload.zip'
        source=folder/'.pending-nc-club-source.sqlite3'
        backup=folder/'pre-import-backup.sqlite3'
        if (folder/'.master-import-complete.json').exists():
            raise ImportErrorSafe(409,'The original source database was already imported.')
        db=connect()
        try:
            if db.execute('SELECT COUNT(*) FROM contacts').fetchone()[0] != 0:
                raise ImportErrorSafe(409,'Live CRM contains contacts: existing records will not be overwritten.')
        finally:
            db.close()
        try:
            with upload.open('wb') as out:
                remaining = size
                while remaining:
                    b=handler.rfile.read(min(1024*1024,remaining))
                    if not b: raise ImportErrorSafe(400,'Upload was interrupted.')
                    out.write(b)
                    remaining-=len(b)
                out.flush()
                os.fsync(out.fileno())
            _copy_database(upload,source)
            trusted=sqlite3.connect(f'file:{source}?mode=ro',uri=True)
            try:
                if trusted.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ImportErrorSafe(422,'Source database failed SQLite integrity check.')
                counts={t:trusted.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0] for t in EXPECTED}
            finally:
                trusted.close()
            if counts != EXPECTED:
                raise ImportErrorSafe(422,'Source database record counts do not match the prepared import.')
            live=connect()
            try:
                if live.execute('SELECT COUNT(*) FROM contacts').fetchone()[0]:
                    raise ImportErrorSafe(409,'Live CRM already contains contacts. Nothing imported.')
                if backup.exists():
                    raise ImportErrorSafe(409,'A pre-import backup is already present; administrator review required.')
                bkp=sqlite3.connect(backup)
                try: live.backup(bkp)
                finally: bkp.close()
                live.execute('ATTACH DATABASE ? AS incoming',(str(source),))
                try:
                    live.execute('BEGIN IMMEDIATE')
                    if live.execute('SELECT COUNT(*) FROM main.contacts').fetchone()[0]:
                        raise ImportErrorSafe(409,'The database changed while the import was preparing.')
                    for table in TABLE_ORDER:
                        live.execute(f'INSERT INTO main.{table} SELECT * FROM incoming.{table}')
                    # Existing suppression records are retained rather than replaced by the imported data.
                    for row in live.execute('SELECT kind,value FROM main.suppression'):
                        kind,value=row['kind'],row['value']
                        if kind=='email':
                            live.execute('UPDATE main.contacts SET do_not_contact=1,eligible_for_outreach=0,status="Do Not Contact" WHERE email=? OR additional_email=?',(value,value))
                        elif kind=='phone':
                            live.execute('UPDATE main.contacts SET do_not_contact=1,eligible_for_outreach=0,status="Do Not Contact" WHERE phone=?',(value,))
                        elif kind=='linkedin':
                            live.execute('UPDATE main.contacts SET do_not_contact=1,eligible_for_outreach=0,status="Do Not Contact" WHERE linkedin=?',(value,))
                    audit(live,user['username'],'master.import.completed','master',{},counts)
                    live.execute('COMMIT')
                except Exception:
                    live.execute('ROLLBACK')
                    raise
                finally:
                    live.execute('DETACH DATABASE incoming')
                confirmed={k:live.execute(f'SELECT COUNT(*) FROM {k}').fetchone()[0] for k in EXPECTED}
                if confirmed != EXPECTED:
                    raise ImportErrorSafe(500,'Post-import count check failed. Contact an administrator.')
            finally: live.close()
            marker=folder/'.master-import-complete.json'
            marker.write_text(json.dumps({'completed_at':now(),'counts':counts,'source_sha256':SOURCE_SHA256}))
            return {'ok':True,'imported':True,'counts':counts,'outreach_enabled':False}
        finally:
            upload.unlink(missing_ok=True)
            source.unlink(missing_ok=True)
    finally:
        LOCK.release()