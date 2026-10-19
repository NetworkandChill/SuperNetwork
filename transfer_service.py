"""One-time, internal Railway service-to-service data migration.

Transport: TLS or Railway internal networking, authenticated with a 48+ byte secret.
Content: 19 SHA-256 checked binary chunks, checked against pinned ZIP hash;
SQLite archive's original SHA and row counts independently checked by import_service.
No contact data is ever added to a GitHub repository or application image.
"""
import hashlib, hmac, json, os, threading
from pathlib import Path
from import_service import perform_import, ImportErrorSafe

ZIP_SHA256 = 'dbfadf10ab0b7e559519ea4c14c257f0db136c196eebd16fe644f2b57a9ff307'
ZIP_SIZE = 19313489
CHUNK_BYTES = 1024 * 1024
CHUNK_COUNT = 19
LOCK = threading.Lock()

class _InternalUpload:
    def __init__(self, file_handle, csrf):
        self.rfile=file_handle
        self.headers={'X-CSRF-Token':csrf, 'Content-Type':'application/octet-stream',
                      'Content-Length':str(ZIP_SIZE)}

def transfer_chunk(handler, db_path, connect, audit, now):
    key=os.getenv('NC_TRANSFER_TOKEN','')
    submitted=handler.headers.get('X-CRM-Transfer-Token','')
    if len(key)<48 or not hmac.compare_digest(submitted, key):
        raise ImportErrorSafe(404,'Not found')
    if handler.headers.get('Content-Type','').split(';')[0]!='application/octet-stream':
        raise ImportErrorSafe(415,'Binary file block required')
    try:
        index=int(handler.headers.get('X-Transfer-Index','-1'))
        length=int(handler.headers.get('Content-Length','0'))
    except ValueError:raise ImportErrorSafe(400,'Invalid block metadata')
    if not (0<=index<CHUNK_COUNT): raise ImportErrorSafe(400,'Unexpected block number')
    expected_length=CHUNK_BYTES if index<CHUNK_COUNT-1 else ZIP_SIZE-CHUNK_BYTES*(CHUNK_COUNT-1)
    if length!=expected_length:raise ImportErrorSafe(400,'Unexpected block length')
    digest=handler.headers.get('X-Transfer-Sha256','')
    if len(digest)!=64 or any(x not in '0123456789abcdef' for x in digest):
        raise ImportErrorSafe(400,'Invalid block fingerprint')
    chunk=handler.rfile.read(length)
    if len(chunk)!=length or hashlib.sha256(chunk).hexdigest()!=digest:
        raise ImportErrorSafe(422,'Block fingerprint mismatch')
    with LOCK:
        folder=db_path.parent
        if (folder/'.master-import-complete.json').exists():
            return {'ok':True,'complete':True,'already_imported':True}
        db=connect()
        try:
            existing=db.execute('SELECT COUNT(*) FROM contacts').fetchone()[0]
        finally:db.close()
        if existing:
            raise ImportErrorSafe(409,'Live CRM has contacts and cannot be overwritten')
        stage=folder/'.nc-transfer-stage'
        stage.mkdir(exist_ok=True,parents=True)
        target=stage/f'{index:03d}.part'
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest()!=digest:
                raise ImportErrorSafe(409,'Stored block does not match the retry')
        else:
            temp=stage/f'{index:03d}.uploading'
            with temp.open('wb') as f:
                f.write(chunk);f.flush();os.fsync(f.fileno())
            temp.rename(target)
        missing=[i for i in range(CHUNK_COUNT) if not (stage/f'{i:03d}.part').exists()]
        if missing:return {'ok':True,'received':index,'remaining':len(missing)}
        archive=stage/'verified-master.zip'
        hash_all=hashlib.sha256()
        with archive.open('wb') as out:
            for i in range(CHUNK_COUNT):
                with (stage/f'{i:03d}.part').open('rb') as inp:
                    while True:
                        block=inp.read(1024*1024)
                        if not block:break
                        hash_all.update(block)
                        out.write(block)
            out.flush();os.fsync(out.fileno())
        if archive.stat().st_size!=ZIP_SIZE or hash_all.hexdigest()!=ZIP_SHA256:
            archive.unlink(missing_ok=True)
            raise ImportErrorSafe(422,'Full archive fingerprint mismatch')
        with archive.open('rb') as uploaded:
            result=perform_import(_InternalUpload(uploaded,'internal-upload'),db_path,connect,audit,now,
                                  {'user':{'role':'Administrator','username':'system-importer'},'csrf':'internal-upload'})
        for x in stage.glob('*.part'):x.unlink(missing_ok=True)
        archive.unlink(missing_ok=True)
        try:stage.rmdir()
        except OSError:pass
        return result