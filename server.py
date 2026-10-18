#!/usr/bin/env python3
"""N&C Club CRM local-first server (standard-library Python 3.10+).
Run: NC_ADMIN_PASSWORD='a-long-random-secret' python server.py
Binds only to loopback by design. Put behind audited HTTPS infrastructure before multi-user remote deployment.
"""
import os,sys,json,sqlite3,datetime,hashlib,hmac,secrets,base64,time,threading,re,urllib.parse,csv,io,zlib,shutil,lzma
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from pathlib import Path
ROOT=Path(__file__).resolve().parent;DB=Path(os.getenv('NC_DB',str(ROOT/'nc_club.sqlite3')))
HOST=os.getenv('NC_HOST','127.0.0.1'); PORT=int(os.getenv('PORT',os.getenv('NC_PORT','8765')))
PUBLIC_TLS=os.getenv('NC_PUBLIC_TLS','0')=='1'
if HOST not in ('127.0.0.1','localhost') and os.getenv('NC_ALLOW_REMOTE')!='1':
 sys.exit('Remote binding disabled unless NC_ALLOW_REMOTE=1. Deploy behind HTTPS with NC_PUBLIC_TLS=1.')
if HOST not in ('127.0.0.1','localhost') and not PUBLIC_TLS:
 sys.exit('Remote CRM requires NC_PUBLIC_TLS=1.')
SESSIONS={};SESSION_LOCK=threading.Lock();FAILED={}
IMPORT_LOCK=threading.Lock()
STAGES=['Imported / Unreviewed','Qualified / Ready to Contact','Contact Attempted','Follow-Up Required','Engaged / Responded','Interested in N&C Club','App Invitation Sent','App Registration Started','Registered / Awaiting Approval','Approved N&C Club Member','Paid Member / Converted','Not Interested / Closed','Do Not Contact']
PROTECTED={'Registered / Awaiting Approval','Approved N&C Club Member','Paid Member / Converted','App Registration Started'}
TIERS={'Essential':'essential','VIP Lite':'vip_lite','VIP Premier':'vip_premier'}
CHANNELS=['Email','Telephone','LinkedIn','Other']
ROLES=['Administrator','Sales Manager','Sales Executive']
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
def conn():
 db=sqlite3.connect(DB,timeout=15,isolation_level=None);db.row_factory=sqlite3.Row;db.execute('PRAGMA foreign_keys=ON');db.execute('PRAGMA busy_timeout=10000');return db
def drow(row):return dict(row) if row is not None else None
def hashpw(password):
 salt=secrets.token_bytes(16); rounds=300000
 return f'pbkdf2_sha256${rounds}${salt.hex()}${hashlib.pbkdf2_hmac("sha256",password.encode(),salt,rounds).hex()}'
def verify(password,encoded):
 try:
  alg,rounds,salt,expected=encoded.split('$');actual=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),int(rounds));return alg=='pbkdf2_sha256' and hmac.compare_digest(actual,bytes.fromhex(expected))
 except Exception:return False
def ensure():
 db=conn()
 db.executescript('''CREATE TABLE IF NOT EXISTS permissions(contact_id TEXT NOT NULL,channel TEXT NOT NULL,state TEXT NOT NULL,lawful_basis TEXT NOT NULL DEFAULT '',evidence TEXT NOT NULL DEFAULT '',reviewer TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(contact_id,channel));
 CREATE INDEX IF NOT EXISTS idx_permitted ON permissions(contact_id,state);
 CREATE TABLE IF NOT EXISTS sessions_info(id TEXT PRIMARY KEY,created_at TEXT);
 ''')
 admin=db.execute('SELECT password_hash FROM team WHERE username=?',('admin',)).fetchone()
 password=os.getenv('NC_ADMIN_PASSWORD','')
 if not admin:
  if len(password)<14:sys.exit('FIRST RUN: Set NC_ADMIN_PASSWORD to a strong password of 14+ characters.')
  db.execute('INSERT INTO team(username,password_hash,role,active) VALUES (?,?,?,1)',('admin',hashpw(password),'Administrator'))
 elif os.getenv('NC_ADMIN_PASSWORD_SYNC','0')=='1':
  # An explicit Railway/operator-managed recovery option; never log or display the secret.
  if len(password)<14:sys.exit('NC_ADMIN_PASSWORD_SYNC requires NC_ADMIN_PASSWORD of 14+ characters.')
  if not verify(password,admin['password_hash']):
   db.execute('UPDATE team SET password_hash=?,role=?,active=1 WHERE username=?',(hashpw(password),'Administrator','admin'))
   db.execute('INSERT INTO audit(actor,action,entity_id,before_json,after_json,occurred_at) VALUES(?,?,?,?,?,?)',('system','admin.password.recovered','admin','{}','{}',now()))
 db.close()
def audit(db,actor,action,entity='',before=None,after=None):
 db.execute('INSERT INTO audit(actor,action,entity_id,before_json,after_json,occurred_at) VALUES(?,?,?,?,?,?)',(actor,action,entity,json.dumps(before or {},ensure_ascii=False),json.dumps(after or {},ensure_ascii=False),now()))
def rolescope(user,alias=''):
 name=alias+'.' if alias else ''
 return (f'{name}owner=?',[user['username']]) if user['role']=='Sales Executive' else ('1=1',[])
def require_contact(db,user,cid):
 row=db.execute('SELECT * FROM contacts WHERE id=?',(cid,)).fetchone()
 if not row:raise ApiError(404,'Contact not found')
 if user['role']=='Sales Executive' and row['owner']!=user['username']:raise ApiError(403,'This contact is not assigned to you')
 return dict(row)
def auth_role(user,*allow):
 if user['role'] not in allow:raise ApiError(403,'Insufficient permission')
class ApiError(Exception):
 def __init__(self,status,message):self.status=status;self.message=message

def get_session(handler):
 raw=handler.headers.get('Cookie','');cookie=SimpleCookie()
 try:cookie.load(raw)
 except:return None
 token=cookie.get('nc_session')
 if not token:return None
 t=token.value
 with SESSION_LOCK:
  ss=SESSIONS.get(t)
  if not ss:return None
  if time.time()-ss['last']>8*3600:SESSIONS.pop(t,None);return None
  ss['last']=time.time()
 return ss

class Handler(BaseHTTPRequestHandler):
 server_version='NCCRM/0.2'
 def log_message(self,fmt,*args):
  # Minimise access logs containing queries with personal information.
  if self.path.startswith('/api/auth'):return
  super().log_message(fmt,*args)
 def headers_common(self):
  self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY')
  self.send_header('Referrer-Policy','no-referrer')
  self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
  self.send_header('Cache-Control','no-store')
  if PUBLIC_TLS: self.send_header('Strict-Transport-Security','max-age=31536000; includeSubDomains')
 def json(self,val,status=200,headers=None):
  raw=json.dumps(val,ensure_ascii=False,default=str).encode('utf8');self.send_response(status);self.headers_common();self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Content-Length',str(len(raw)))
  if headers:
   for k,v in headers.items():self.send_header(k,v)
  self.end_headers();self.wfile.write(raw)
 def read(self):
  length=int(self.headers.get('Content-Length',0))
  if length>1_500_000:raise ApiError(413,'Request too large')
  try:return json.loads(self.rfile.read(length) or '{}')
  except:raise ApiError(400,'Invalid JSON body')
 def route(self,method):
  url=urllib.parse.urlsplit(self.path);path=url.path;q={k:v[0] for k,v in urllib.parse.parse_qs(url.query).items()}
  if method=='GET' and not path.startswith('/api/'):
   return self.static(path)
  if path=='/api/auth/login' and method=='POST':return self.login()
  if path=='/api/admin/import-chunk' and method=='POST':return self.import_chunk()
  ss=get_session(self)
  if not ss:raise ApiError(401,'Please sign in')
  user=ss['user']
  if method!='GET':
   if self.headers.get('X-CSRF-Token')!=ss['csrf']:raise ApiError(403,'Invalid session request token')
   if not self.headers.get('Content-Type','').startswith('application/json'):raise ApiError(415,'JSON required')
  if path=='/api/auth/logout' and method=='POST':
   with SESSION_LOCK:SESSIONS.pop(ss['token'],None)
   return self.json({'ok':True},headers={'Set-Cookie':'nc_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/'+('; Secure' if PUBLIC_TLS else '')})
  if path=='/api/session' and method=='GET':return self.json({'user':user,'csrf':ss['csrf']})
  db=conn()
  try:
   if path=='/api/overview' and method=='GET':return self.overview(db,user)
   if path=='/api/contacts' and method=='GET':return self.contacts(db,user,q)
   if path=='/api/pipeline' and method=='GET':return self.pipeline(db,user)
   if path=='/api/organizations' and method=='GET':return self.organizations(db,user,q)
   if path=='/api/tasks' and method=='GET':return self.tasks(db,user,q)
   if path=='/api/tasks' and method=='POST':return self.add_task(db,user,self.read())
   if path=='/api/duplicates' and method=='GET':return self.duplicates(db,user,q)
   if path=='/api/imports' and method=='GET':return self.imports(db,user)
   if path=='/api/team' and method=='GET':return self.team(db,user)
   if path=='/api/team' and method=='POST':return self.add_user(db,user,self.read())
   if path=='/api/settings' and method=='GET':return self.settings(db,user)
   if path=='/api/settings' and method=='POST':return self.save_settings(db,user,self.read())
   if path=='/api/sales' and method=='GET':return self.sales(db,user)
   if path=='/api/subscriptions' and method=='GET':return self.subscriptions(db,user,q)
   if path=='/api/subscriptions' and method=='POST':return self.add_subscription(db,user,self.read())
   if path=='/api/audit' and method=='GET':return self.audit_list(db,user,q)
   if path=='/api/export' and method=='GET':return self.export(db,user,q)
   m=re.fullmatch(r'/api/contacts/(NC-\d{6})',path)
   if m and method=='GET':return self.contact(db,user,m[1])
   m=re.fullmatch(r'/api/contacts/(NC-\d{6})/(update|activity|permission|suppress|task)',path)
   if m and method=='POST':return self.contact_action(db,user,m[1],m[2],self.read())
   m=re.fullmatch(r'/api/tasks/(\d+)/(complete|reopen)',path)
   if m and method=='POST':return self.task_change(db,user,int(m[1]),m[2])
   m=re.fullmatch(r'/api/duplicates/(\d+)/(reject|merge|reverse)',path)
   if m and method=='POST':return self.dupe_action(db,user,int(m[1]),m[2])
   m=re.fullmatch(r'/api/subscriptions/(\d+)/verify',path)
   if m and method=='POST':return self.verify_sub(db,user,int(m[1]),self.read())
   raise ApiError(404,'Unknown endpoint')
  finally:db.close()
 def do_GET(self):
  try:self.route('GET')
  except ApiError as e:self.json({'error':e.message},e.status)
  except Exception as e:print('Error GET',type(e).__name__,str(e)[:250],file=sys.stderr);self.json({'error':'Server error'},500)
 def do_POST(self):
  try:self.route('POST')
  except ApiError as e:self.json({'error':e.message},e.status)
  except Exception as e:print('Error POST',type(e).__name__,str(e)[:250],file=sys.stderr);self.json({'error':'Server error'},500)
 def import_chunk(self):
  # Administrator-only bulk import: normal authenticated session and CSRF protection.
  ss=get_session(self)
  if not ss:raise ApiError(401,'Please sign in')
  auth_role(ss['user'],'Administrator')
  if self.headers.get('X-CSRF-Token')!=ss['csrf']:raise ApiError(403,'Invalid CSRF token')
  sid=os.getenv('NC_IMPORT_SESSION','')
  if self.headers.get('X-CRM-Import-Session')!=sid or len(sid)<16:raise ApiError(403,'Invalid import session')
  if self.headers.get('Content-Type')!='application/octet-stream':raise ApiError(415,'Binary data required')
  try:
   length=int(self.headers.get('Content-Length','0'))
   seq=int(self.headers.get('X-Import-Sequence','-1'))
   total=int(self.headers.get('X-Import-Total','0'))
  except ValueError:raise ApiError(400,'Invalid import metadata')
  if not (1<=length<=2200000 and 0<=seq<total<=80):raise ApiError(413,'Import block or count invalid')
  checksum=self.headers.get('X-Import-Block-Sha256','')
  fullsum=self.headers.get('X-Import-Full-Sha256','')
  if not (re.fullmatch(r'[0-9a-f]{64}',checksum) and re.fullmatch(r'[0-9a-f]{64}',fullsum)):raise ApiError(400,'Invalid checksum')
  with IMPORT_LOCK:
   p=DB.parent;part=p/'.supernetwork-import.xz';statefile=p/'.supernetwork-import.json'
   if (p/'.supernetwork-import.complete').exists():raise ApiError(409,'Import already completed')
   try:state=json.loads(statefile.read_text()) if statefile.exists() else {'next':0,'total':total,'full_sha256':fullsum}
   except:raise ApiError(409,'Invalid import state')
   if state['total']!=total or state['full_sha256']!=fullsum:raise ApiError(409,'This is not the active import')
   if seq!=state['next']:
    if seq==state['next']-1 and checksum==state.get('last_checksum'):
     return self.json({'ok':True,'sequence':seq,'next':state['next'],'retry':True})
    raise ApiError(409,f'Expected import block {state["next"]}')
   b=self.rfile.read(length)
   if len(b)!=length or hashlib.sha256(b).hexdigest()!=checksum:raise ApiError(400,'Import block checksum mismatch')
   with open(part,'ab') as handle:
    handle.write(b);handle.flush();os.fsync(handle.fileno())
   state.update(next=seq+1,last_checksum=checksum)
   statefile.write_text(json.dumps(state))
   if seq!=total-1:return self.json({'ok':True,'sequence':seq,'next':state['next']})
   with open(part,'rb') as whole:
    if hashlib.file_digest(whole,'sha256').hexdigest()!=fullsum:raise ApiError(400,'Import archive checksum mismatch')
   temp=p/'.supernetwork-source.sqlite3'
   try:
    # 45 MB clean consolidated source DB; cap expansion to prevent decompression bombs.
    size=0
    with lzma.open(part,'rb') as src,open(temp,'wb') as out:
     while True:
      chunk=src.read(1024*1024)
      if not chunk:break
      size+=len(chunk)
      if size>100*1024*1024:raise ApiError(413,'Source database exceeds size limit')
      out.write(chunk)
    source=sqlite3.connect(f'file:{temp}?mode=ro',uri=True)
    try:
     valid=source.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
     required={'contacts':31596,'organizations':3472,'source_rows':59205,'aliases':28262,'duplicate_candidates':1957,'merge_log':19575,'import_batches':20}
     counts={t:source.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in required}
    finally:source.close()
    if not valid or counts!=required:raise ApiError(422,'Source integrity or record-count validation failed')
    live=conn()
    try:
     if live.execute('SELECT COUNT(*) FROM contacts').fetchone()[0]:raise ApiError(409,'CRM already has records; refusing to overwrite')
     # Durable pre-import backup, followed by an atomic database transaction.
     backup=sqlite3.connect(p/'pre-import-backup.sqlite3')
     try:live.backup(backup)
     finally:backup.close()
     live.execute('ATTACH DATABASE ? AS imported',(str(temp),))
     try:
      live.execute('BEGIN IMMEDIATE')
      for table in ['organizations','contacts','source_rows','aliases','duplicate_candidates','merge_log','import_batches']:
       live.execute('INSERT INTO main.'+table+' SELECT * FROM imported.'+table)
      # Preserve any existing central suppression records, including re-import blocks.
      for row in live.execute('SELECT kind,value FROM suppression'):
       if row['kind'] in ('email','phone','linkedin'):
        live.execute('UPDATE contacts SET do_not_contact=1,eligible_for_outreach=0,status="Do Not Contact" WHERE '+('email=? OR additional_email=?' if row['kind']=='email' else 'phone=?' if row['kind']=='phone' else 'linkedin=?'),(row['value'],row['value']) if row['kind']=='email' else (row['value'],))
      audit(live,'system','import.completed','master',{},counts)
      live.execute('COMMIT')
     except:
      live.execute('ROLLBACK');raise
     finally:live.execute('DETACH DATABASE imported')
    finally:live.close()
    (p/'.supernetwork-import.complete').write_text(json.dumps({'at':now(),'counts':counts,'sha256':fullsum}))
    statefile.unlink(missing_ok=True);part.unlink(missing_ok=True);temp.unlink(missing_ok=True)
    return self.json({'ok':True,'complete':True,'counts':counts})
   except Exception:
    # Retain partial archive and state for troubleshooting. Never leak record contents in errors.
    raise
 def static(self,path):
  files={'/':'index.html','/index.html':'index.html','/app.js':'app.js','/styles.css':'styles.css'}
  if path not in files:raise ApiError(404,'Not found')
  fp=ROOT/'web'/files[path];blob=fp.read_bytes();self.send_response(200);self.headers_common();self.send_header('Content-Type',('application/javascript' if fp.suffix=='.js' else 'text/css' if fp.suffix=='.css' else 'text/html')+'; charset=utf-8');self.send_header('Content-Length',str(len(blob)));self.end_headers();self.wfile.write(blob)
 def login(self):
  p=self.read();username=str(p.get('username','')).strip().lower();pw=str(p.get('password',''))
  key=(username,self.client_address[0]);stamp=time.time();attempts=[t for t in FAILED.get(key,[]) if stamp-t<600]
  if len(attempts)>=8:raise ApiError(429,'Too many sign-in attempts; try again later')
  db=conn()
  try:row=db.execute('SELECT username,password_hash,role,active FROM team WHERE username=?',(username,)).fetchone()
  finally:db.close()
  if not row or not row['active'] or not verify(pw,row['password_hash']):
   attempts.append(stamp);FAILED[key]=attempts;raise ApiError(401,'Invalid credentials')
  FAILED.pop(key,None);token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(30);u={'username':row['username'],'role':row['role']}
  with SESSION_LOCK:SESSIONS[token]={'user':u,'csrf':csrf,'token':token,'last':time.time()}
  self.json({'user':u,'csrf':csrf},headers={'Set-Cookie':f'nc_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'+('; Secure' if PUBLIC_TLS else '')})
 def overview(self,db,user):
  clause,params=rolescope(user)
  def n(condition='1=1',extra=()):return db.execute(f'SELECT COUNT(*) FROM contacts WHERE {clause} AND ({condition})',params+list(extra)).fetchone()[0]
  tasks_clause='assignee=?' if user['role']=='Sales Executive' else '1=1';taskparam=[user['username']] if user['role']=='Sales Executive' else []
  items={'contacts':n(),'unreviewed':n("status='Imported / Unreviewed'"),'assigned':n("owner<>''"),'eligible':n('eligible_for_outreach=1 AND do_not_contact=0'),
   'missing_email':n("email=''"),'missing_contact':n("email='' AND phone=''"),'attempted':n("last_contact<>''"),'engaged':n("status IN ('Engaged / Responded','Interested in N&C Club')"),
   'interested':n("status='Interested in N&C Club'"),'invited':n("status='App Invitation Sent'"),'registered':n("status IN ('Registered / Awaiting Approval','Approved N&C Club Member','Paid Member / Converted')"),
   'approved':n("status IN ('Approved N&C Club Member','Paid Member / Converted')"),'paid':n("status='Paid Member / Converted'"),
   'open_tasks':db.execute(f"SELECT COUNT(*) FROM tasks WHERE {tasks_clause} AND state='Open'",taskparam).fetchone()[0],
   'overdue':db.execute(f"SELECT COUNT(*) FROM tasks WHERE {tasks_clause} AND state='Open' AND due_at < ?",taskparam+[datetime.date.today().isoformat()]).fetchone()[0],
   'due_today':db.execute(f"SELECT COUNT(*) FROM tasks WHERE {tasks_clause} AND state='Open' AND substr(due_at,1,10)=?",taskparam+[datetime.date.today().isoformat()]).fetchone()[0]}
  if user['role']!='Sales Executive':
   items['organizations']=db.execute('SELECT COUNT(*) FROM organizations').fetchone()[0]
   items['duplicates']=db.execute("SELECT COUNT(*) FROM duplicate_candidates WHERE decision='Pending'").fetchone()[0]
  row=db.execute('SELECT COUNT(*) n,COALESCE(SUM(amount),0) gross,COALESCE(SUM(commission),0) commissions FROM subscriptions WHERE status=?'+(' AND salesperson=?' if user['role']=='Sales Executive' else ''),['Verified']+([user['username']] if user['role']=='Sales Executive' else [])).fetchone()
  items.update({'verified_subscriptions':row['n'],'verified_gross':row['gross'],'verified_commissions':row['commissions']})
  return self.json(items)
 def parse_filter(self,user,q):
  clause,pars=rolescope(user);where=[clause]
  if q.get('search'):
   s='%'+q['search'][:140].replace('%','\\%').replace('_','\\_')+'%'
   where.append("(full_name LIKE ? ESCAPE '\\' OR company LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')");pars+= [s,s,s]
  for k,field in [('status','status'),('category','category'),('country','country'),('owner','owner'),('tier','membership_tier')]:
   if q.get(k):where.append(field+'=?');pars.append(q[k][:150])
  if q.get('uncontacted')=='1':where.append("last_contact=''")
  if q.get('eligible')=='1':where.append('eligible_for_outreach=1 AND do_not_contact=0')
  if q.get('missing')=='1':where.append("email='' AND phone=''")
  return ' AND '.join(f'({w})' for w in where),pars
 def contacts(self,db,user,q):
  where,args=self.parse_filter(user,q);page=max(1,min(int(q.get('page','1')),999999));size=max(10,min(int(q.get('page_size','25')),100))
  valid={'name':'full_name COLLATE NOCASE','company':'company COLLATE NOCASE','updated':'updated_at','contacted':'last_contact','followup':'next_followup'}
  sort=valid.get(q.get('sort','name'),valid['name']);direction='DESC' if q.get('dir','asc').lower()=='desc' else 'ASC'
  total=db.execute('SELECT COUNT(*) FROM contacts WHERE '+where,args).fetchone()[0]
  rows=[dict(r) for r in db.execute('SELECT id,full_name,job_title,company,category,email,phone,country,city,status,owner,last_contact,next_followup,do_not_contact,eligible_for_outreach,membership_tier FROM contacts WHERE '+where+' ORDER BY '+sort+' '+direction+',id ASC LIMIT ? OFFSET ?',args+[size,(page-1)*size])]
  return self.json({'total':total,'page':page,'page_size':size,'rows':rows})
 def contact(self,db,user,cid):
  row=require_contact(db,user,cid)
  origins=[dict(r) for r in db.execute('SELECT source_file,sheet,row_number,imported_at FROM source_rows WHERE entity_type=? AND entity_id=? ORDER BY id DESC LIMIT 120',('contact',cid))]
  activities=[dict(r) for r in db.execute('SELECT id,actor,kind,note,channel,verified,created_at FROM activity WHERE contact_id=? ORDER BY created_at DESC,id DESC LIMIT 200',(cid,))]
  tasks=[dict(r) for r in db.execute('SELECT * FROM tasks WHERE contact_id=? ORDER BY due_at DESC LIMIT 100',(cid,))]
  perms=[dict(r) for r in db.execute('SELECT * FROM permissions WHERE contact_id=?',(cid,))]
  aliases=[dict(r) for r in db.execute('SELECT kind,value FROM aliases WHERE contact_id=?',(cid,))]
  return self.json({'contact':row,'origins':origins,'activities':activities,'tasks':tasks,'permissions':perms,'aliases':aliases})
 def contact_action(self,db,user,cid,action,p):
  before=require_contact(db,user,cid)
  if action=='update':
   allowed=['first_name','last_name','job_title','company','industry','category','email','additional_email','phone','country','city','linkedin','website','owner','status','membership_tier']
   upd={k:str(v).strip()[:500] for k,v in p.items() if k in allowed and v is not None}
   if not upd:raise ApiError(400,'Nothing to update')
   if 'owner' in upd:
    auth_role(user,'Administrator','Sales Manager')
    if upd['owner'] and not db.execute('SELECT 1 FROM team WHERE username=? AND active=1',(upd['owner'],)).fetchone():raise ApiError(400,'Assigned owner must be an active team account')
   if 'status' in upd:
    if upd['status'] not in STAGES:raise ApiError(400,'Unknown pipeline stage')
    if upd['status'] in PROTECTED:raise ApiError(403,'App status requires a verified integration or approved evidence workflow')
    if before['do_not_contact'] and upd['status']!='Do Not Contact':raise ApiError(403,'Suppressed contact cannot enter pipeline')
    if before['membership_status']=='Verified' and upd['status']!=before['status']:raise ApiError(403,'Verified member status cannot be changed manually')
    if upd['status'] in STAGES[1:9] and not before['eligible_for_outreach'] and upd['status']!='Not Interested / Closed':raise ApiError(403,'Outreach permission must be reviewed first')
   if upd.get('status')=='Do Not Contact':return self.contact_action(db,user,cid,'suppress',{'reason':'Contact opted out / staff suppression'})
   upd['updated_at']=now()
   for key,kind in [('email','email'),('additional_email','email'),('phone','phone'),('linkedin','linkedin')]:
    if key in upd and upd[key] and db.execute('SELECT 1 FROM suppression WHERE kind=? AND value=?',(kind,upd[key].lower())).fetchone():raise ApiError(403,'Updated contact detail is on the central suppression list')
   db.execute('BEGIN');db.execute('UPDATE contacts SET '+','.join(f'{k}=?' for k in upd)+' WHERE id=?',list(upd.values())+[cid])
   for key,kind in [('email','email'),('additional_email','email'),('phone','phone'),('linkedin','linkedin')]:
    if key in upd and upd[key]:db.execute('INSERT OR IGNORE INTO aliases(contact_id,kind,value) VALUES(?,?,?)',(cid,kind,upd[key].lower()))
   audit(db,user['username'],'contact.update',cid,{k:before.get(k) for k in upd},upd);db.execute('COMMIT')
   return self.json({'ok':True})
  if action=='activity':
   kind=str(p.get('kind','Note'))[:120];note=str(p.get('note','')).strip()[:10000];channel=str(p.get('channel',''))[:80]
   if kind not in ['Note','Contact Reviewed','First Contact Attempted','Contact Replied','Follow-Up Scheduled','Follow-Up Completed','Interested','App Invitation Sent','No Response','Not Interested','Contact Assigned']:
    raise ApiError(400,'Unknown activity')
   outbound={'First Contact Attempted','App Invitation Sent'}
   if kind in outbound:
    if not before['eligible_for_outreach'] or before['do_not_contact']:raise ApiError(403,'Not permitted: verify marketing permission before outreach')
    if channel not in CHANNELS:raise ApiError(403,'Select a reviewed and permitted outreach channel')
    permission=db.execute('SELECT state,lawful_basis,evidence FROM permissions WHERE contact_id=? AND channel=?',(cid,channel)).fetchone()
    if not permission or permission['state']!='Allowed' or not permission['lawful_basis'] or not permission['evidence']:raise ApiError(403,'This channel has no recorded permission approval')
   db.execute('BEGIN');db.execute('INSERT INTO activity(contact_id,actor,kind,note,channel,verified,created_at) VALUES(?,?,?,?,?,0,?)',(cid,user['username'],kind,note,channel,now()))
   changes={'updated_at':now()}
   stage={'First Contact Attempted':'Contact Attempted','Contact Replied':'Engaged / Responded','Interested':'Interested in N&C Club','App Invitation Sent':'App Invitation Sent','No Response':'Follow-Up Required','Not Interested':'Not Interested / Closed'}
   if kind in outbound:changes['last_contact']=datetime.date.today().isoformat()
   if kind in stage and not before['do_not_contact'] and (before['eligible_for_outreach'] or kind=='Not Interested'):changes['status']=stage[kind]
   db.execute('UPDATE contacts SET '+','.join(k+'=?' for k in changes)+' WHERE id=?',list(changes.values())+[cid]);audit(db,user['username'],'contact.activity',cid,{},dict(kind=kind,note=note,channel=channel));db.execute('COMMIT')
   return self.json({'ok':True})
  if action=='permission':
   channel=str(p.get('channel',''));state=str(p.get('state',''));basis=str(p.get('lawful_basis','')).strip()[:250];evidence=str(p.get('evidence','')).strip()[:2000]
   if channel not in CHANNELS or state not in ['Allowed','Unknown','Not allowed']:raise ApiError(400,'Invalid permission state or channel')
   if state=='Allowed' and (not evidence or not basis):raise ApiError(400,'Document the legal basis, channel assessment and evidence before allowing outreach')
   db.execute('BEGIN');db.execute('INSERT INTO permissions(contact_id,channel,state,lawful_basis,evidence,reviewer,updated_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(contact_id,channel) DO UPDATE SET state=excluded.state,lawful_basis=excluded.lawful_basis,evidence=excluded.evidence,reviewer=excluded.reviewer,updated_at=excluded.updated_at',(cid,channel,state,basis,evidence,user['username'],now()))
   permitted=db.execute("SELECT COUNT(*) FROM permissions WHERE contact_id=? AND state='Allowed' AND evidence<>'' AND lawful_basis<>''",(cid,)).fetchone()[0]>0
   eligible=int(permitted and not before['do_not_contact'])
   db.execute('UPDATE contacts SET eligible_for_outreach=?,marketing_permission=?,lawful_basis=?,updated_at=? WHERE id=?',(eligible,'Reviewed' if permitted else 'Not cleared',basis,now(),cid))
   audit(db,user['username'],'permission.review',cid,{},dict(channel=channel,state=state,lawful_basis=basis,evidence=evidence));db.execute('COMMIT')
   return self.json({'ok':True})
  if action=='suppress':
   reason=str(p.get('reason','Opt-out'))[:400];db.execute('BEGIN')
   for kind,val in [('email',before['email']),('email',before['additional_email']),('phone',before['phone']),('linkedin',before['linkedin'])]:
    if val:db.execute('INSERT OR IGNORE INTO suppression(kind,value,reason,created_at) VALUES(?,?,?,?)',(kind,val.lower(),reason,now()))
   db.execute("UPDATE contacts SET status='Do Not Contact',do_not_contact=1,eligible_for_outreach=0,updated_at=? WHERE id=?",(now(),cid))
   db.execute("UPDATE tasks SET state='Cancelled' WHERE contact_id=? AND state='Open'",(cid,));audit(db,user['username'],'contact.suppress',cid,{},dict(reason=reason));db.execute('COMMIT')
   return self.json({'ok':True})
  if action=='task':p['contact_id']=cid;return self.add_task(db,user,p)
 def add_task(self,db,user,p):
  cid=str(p.get('contact_id',''));ct=require_contact(db,user,cid)
  label=str(p.get('label','Follow up')).strip()[:250];due=str(p.get('due_at','')).strip()[:32];priority=str(p.get('priority','Normal'));assignee=str(p.get('assignee',ct['owner'] or user['username']))[:80]
  try:datetime.datetime.fromisoformat(due[:19]) if len(due)>10 else datetime.date.fromisoformat(due)
  except:raise ApiError(400,'Please supply a valid ISO date or date-time')
  if priority not in ['Low','Normal','High']:raise ApiError(400,'Invalid priority')
  if user['role']=='Sales Executive' and assignee!=user['username']:raise ApiError(403,'Cannot assign tasks to other users')
  db.execute('BEGIN');cur=db.execute('INSERT INTO tasks(contact_id,assignee,label,due_at,priority,state,created_at) VALUES(?,?,?,?,?,"Open",?)',(cid,assignee,label,due,priority,now()))
  audit(db,user['username'],'task.create',cid,{},dict(id=cur.lastrowid,assignee=assignee,due_at=due,label=label));db.execute('COMMIT');return self.json({'ok':True,'id':cur.lastrowid})
 def task_change(self,db,user,tid,action):
  row=db.execute('SELECT t.*,c.owner FROM tasks t JOIN contacts c ON c.id=t.contact_id WHERE t.id=?',(tid,)).fetchone()
  if not row:raise ApiError(404,'Task not found')
  if user['role']=='Sales Executive' and row['owner']!=user['username']:raise ApiError(403,'Not your contact')
  state='Completed' if action=='complete' else 'Open';db.execute('UPDATE tasks SET state=? WHERE id=?',(state,tid));audit(db,user['username'],'task.'+action,row['contact_id'],{'state':row['state']},{'state':state});return self.json({'ok':True})
 def tasks(self,db,user,q):
  where,pars=rolescope(user,'c');more=[where]
  if q.get('state','Open')!='All':more.append('t.state=?');pars.append(q.get('state','Open'))
  rows=[dict(r) for r in db.execute('SELECT t.*,c.full_name,c.company FROM tasks t JOIN contacts c ON c.id=t.contact_id WHERE '+' AND '.join(more)+' ORDER BY t.due_at ASC LIMIT 300',pars)]
  return self.json({'rows':rows})
 def pipeline(self,db,user):
  where,pars=rolescope(user);rows=[dict(r) for r in db.execute(f'SELECT status,COUNT(*) n FROM contacts WHERE {where} GROUP BY status',pars)];return self.json({'rows':rows,'stages':STAGES})
 def organizations(self,db,user,q):
  auth_role(user,'Administrator','Sales Manager');s='%'+q.get('search','')[:100]+'%';page=max(1,int(q.get('page','1')))
  total=db.execute('SELECT COUNT(*) FROM organizations WHERE name LIKE ? OR country LIKE ?',(s,s)).fetchone()[0]
  rows=[dict(r) for r in db.execute('SELECT id,name,website,email,location,country,type FROM organizations WHERE name LIKE ? OR country LIKE ? ORDER BY name COLLATE NOCASE LIMIT 30 OFFSET ?',(s,s,(page-1)*30))]
  return self.json({'rows':rows,'total':total,'page':page})
 def duplicates(self,db,user,q):
  auth_role(user,'Administrator');state=q.get('state','Pending');page=max(1,int(q.get('page','1')))
  total=db.execute('SELECT COUNT(*) FROM duplicate_candidates WHERE decision=?',(state,)).fetchone()[0]
  rows=[dict(r) for r in db.execute('SELECT d.id,d.score,d.reason,d.decision,d.contact_id,d.other_contact_id,a.full_name a_name,a.company a_company,a.email a_email,b.full_name b_name,b.company b_company,b.email b_email FROM duplicate_candidates d JOIN contacts a ON a.id=d.contact_id JOIN contacts b ON b.id=d.other_contact_id WHERE d.decision=? ORDER BY d.score DESC,d.id LIMIT 30 OFFSET ?', (state,(page-1)*30))]
  return self.json({'rows':rows,'total':total,'page':page})
 def dupe_action(self,db,user,did,action):
  auth_role(user,'Administrator');d=drow(db.execute('SELECT * FROM duplicate_candidates WHERE id=?',(did,)).fetchone())
  if not d:raise ApiError(404,'Candidate not found')
  if action=='reject':
   if d['decision']!='Pending':raise ApiError(409,'Already reviewed')
   db.execute("UPDATE duplicate_candidates SET decision='Rejected' WHERE id=?",(did,));audit(db,user['username'],'duplicate.reject',str(did),{},d);return self.json({'ok':True})
  if action=='reverse':raise ApiError(409,'Automatic reversal not yet supported; backup and merge snapshot available for administrator recovery')
  if d['decision']!='Pending':raise ApiError(409,'Already reviewed')
  a=drow(db.execute('SELECT * FROM contacts WHERE id=?',(d['contact_id'],)).fetchone());b=drow(db.execute('SELECT * FROM contacts WHERE id=?',(d['other_contact_id'],)).fetchone())
  if not a or not b:raise ApiError(404,'Contact records unavailable')
  # Honor restrictions and never accidentally unsuppress one of the two identities.
  keep=a;remove=b;fields=['first_name','last_name','job_title','company','industry','category','email','additional_email','phone','country','city','linkedin','website'];upd={k:remove[k] for k in fields if not keep[k] and remove[k]}
  doc={'retained_before':a,'merged_before':b,'source_ids':[r[0] for r in db.execute('SELECT id FROM source_rows WHERE entity_type="contact" AND entity_id=?',(b['id'],))], 'activity_ids':[r[0] for r in db.execute('SELECT id FROM activity WHERE contact_id=?',(b['id'],))], 'task_ids':[r[0] for r in db.execute('SELECT id FROM tasks WHERE contact_id=?',(b['id'],))], 'subscription_ids':[r[0] for r in db.execute('SELECT id FROM subscriptions WHERE contact_id=?',(b['id'],))], 'aliases':[dict(r) for r in db.execute('SELECT kind,value FROM aliases WHERE contact_id=?',(b['id'],))], 'permissions_removed':[dict(r) for r in db.execute('SELECT * FROM permissions WHERE contact_id=?',(b['id'],))], 'permissions_retained':[dict(r) for r in db.execute('SELECT * FROM permissions WHERE contact_id=?',(a['id'],))]}
  db.execute('BEGIN')
  if upd:db.execute('UPDATE contacts SET '+','.join(k+'=?' for k in upd)+' WHERE id=?',list(upd.values())+[a['id']])
  for alias in doc['aliases']:db.execute('INSERT OR IGNORE INTO aliases(contact_id,kind,value) VALUES(?,?,?)',(a['id'],alias['kind'],alias['value']))
  for field in ['email','additional_email','phone','linkedin']:
   if b[field]:db.execute('INSERT OR IGNORE INTO aliases(contact_id,kind,value) VALUES(?,?,?)',(a['id'],'email' if 'email' in field else field,b[field]))
  for table in ['source_rows','activity','tasks','subscriptions']:
   db.execute(f'UPDATE {table} SET '+('entity_id' if table=='source_rows' else 'contact_id')+'=? WHERE '+('entity_id' if table=='source_rows' else 'contact_id')+'=?'+(' AND entity_type="contact"' if table=='source_rows' else ''),(a['id'],b['id']))
  if a['do_not_contact'] or b['do_not_contact']:
   db.execute('UPDATE contacts SET do_not_contact=1,eligible_for_outreach=0,status="Do Not Contact" WHERE id=?',(a['id'],))
  for perm in doc['permissions_removed']:
   existing=db.execute('SELECT state FROM permissions WHERE contact_id=? AND channel=?',(a['id'],perm['channel'])).fetchone()
   if not existing:db.execute('INSERT INTO permissions(contact_id,channel,state,lawful_basis,evidence,reviewer,updated_at) VALUES(?,?,?,?,?,?,?)',(a['id'],perm['channel'],'Unknown',perm['lawful_basis'],'MERGED — re-review before outreach: '+perm['evidence'],user['username'],now()))
   else:db.execute('UPDATE permissions SET state=?,evidence=?,reviewer=?,updated_at=? WHERE contact_id=? AND channel=?',('Not allowed' if existing['state']=='Not allowed' or perm['state']=='Not allowed' else 'Unknown','Merged another source permission; must re-review',user['username'],now(),a['id'],perm['channel']))
  db.execute('UPDATE permissions SET state="Unknown" WHERE contact_id=? AND state="Allowed"',(a['id'],))
  db.execute('UPDATE contacts SET eligible_for_outreach=0,marketing_permission="Re-review after merge" WHERE id=?',(a['id'],))
  db.execute('DELETE FROM aliases WHERE contact_id=?',(b['id'],));db.execute('DELETE FROM permissions WHERE contact_id=?',(b['id'],));db.execute('DELETE FROM contacts WHERE id=?',(b['id'],))
  db.execute("UPDATE duplicate_candidates SET decision='Merged' WHERE id=?",(did,))
  db.execute("UPDATE duplicate_candidates SET decision='Superseded' WHERE decision='Pending' AND (contact_id=? OR other_contact_id=?)",(b['id'],b['id']))
  db.execute('INSERT INTO merge_log(retained_id,merged_id,reason,backup_json_z,occurred_at,actor) VALUES(?,?,?,?,?,?)',(a['id'],b['id'],'manual review #'+str(did),zlib.compress(json.dumps(doc,ensure_ascii=False).encode()),now(),user['username']))
  audit(db,user['username'],'duplicate.merge',str(did),{'a':a['id'],'b':b['id']}, {'retained':a['id']});db.execute('COMMIT');return self.json({'ok':True,'retained_id':a['id']})
 def imports(self,db,user):
  auth_role(user,'Administrator','Sales Manager');report=json.loads((ROOT/'import_report.json').read_text());return self.json(report)
 def settings(self,db,user):
  rows={r['k']:r['v'] for r in db.execute('SELECT * FROM settings')};return self.json(rows)
 def save_settings(self,db,user,p):
  auth_role(user,'Administrator')
  allowed={'price_essential','price_vip_lite','price_vip_premier','commission_essential','commission_vip_lite','commission_vip_premier','target_monthly','target_growth'}
  for k,v in p.items():
   if k not in allowed:continue
   try:amount=float(v)
   except:raise ApiError(400,'Invalid numeric setting')
   if not (0<=amount<=1000000):raise ApiError(400,'Setting is out of range')
   db.execute('INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)',(k,str(amount)));audit(db,user['username'],'settings.update',k,{},dict(value=amount))
  return self.json({'ok':True})
 def team(self,db,user):
  auth_role(user,'Administrator','Sales Manager');return self.json({'rows':[dict(r) for r in db.execute('SELECT username,role,active FROM team ORDER BY username')]})
 def add_user(self,db,user,p):
  auth_role(user,'Administrator');name=str(p.get('username','')).lower().strip();pwd=str(p.get('password',''));role=p.get('role','Sales Executive')
  if not re.fullmatch(r'[a-z0-9_.-]{3,35}',name) or len(pwd)<14 or role not in ROLES:raise ApiError(400,'Username, role or password invalid (minimum 14 characters)')
  try:db.execute('INSERT INTO team(username,password_hash,role,active) VALUES(?,?,?,1)',(name,hashpw(pwd),role))
  except sqlite3.IntegrityError:raise ApiError(409,'Username already exists')
  audit(db,user['username'],'team.create',name,{},dict(role=role));return self.json({'ok':True})
 def sales(self,db,user):
  w='WHERE s.status="Verified"'+(' AND s.salesperson=?' if user['role']=='Sales Executive' else '');params=[user['username']] if user['role']=='Sales Executive' else []
  rows=[dict(r) for r in db.execute(f'SELECT s.tier,s.salesperson,COUNT(*) AS n,SUM(s.amount) AS gross,SUM(s.commission) AS commission FROM subscriptions s {w} GROUP BY s.tier,s.salesperson ORDER BY gross DESC',params)]
  settings={r['k']:float(r['v']) for r in db.execute('SELECT * FROM settings')};return self.json({'rows':rows,'settings':settings})
 def subscriptions(self,db,user,q):
  where='1=1';args=[]
  if user['role']=='Sales Executive':where='s.salesperson=?';args=[user['username']]
  rows=[dict(r) for r in db.execute('SELECT s.*,c.full_name,c.company FROM subscriptions s JOIN contacts c ON s.contact_id=c.id WHERE '+where+' ORDER BY s.id DESC LIMIT 150',args)]
  return self.json({'rows':rows})
 def add_subscription(self,db,user,p):
  cid=str(p.get('contact_id',''));c=require_contact(db,user,cid);tier=str(p.get('tier',''))
  if tier not in TIERS:raise ApiError(400,'Select a valid annual tier')
  if c['do_not_contact']:raise ApiError(403,'Suppressed contact')
  suffix=TIERS[tier];price=float(db.execute('SELECT v FROM settings WHERE k=?',('price_'+suffix,)).fetchone()[0]);commission=float(db.execute('SELECT v FROM settings WHERE k=?',('commission_'+suffix,)).fetchone()[0]);salesperson=c['owner'] or user['username']
  db.execute('BEGIN');r=db.execute('INSERT INTO subscriptions(contact_id,tier,amount,commission,status,salesperson) VALUES(?,?,?,?,"Pending",?)',(cid,tier,price,commission,salesperson));audit(db,user['username'],'subscription.pending',cid,{},dict(tier=tier,price=price,id=r.lastrowid));db.execute('COMMIT');return self.json({'ok':True,'id':r.lastrowid})
 def verify_sub(self,db,user,subid,p):
  auth_role(user,'Administrator');ref=str(p.get('verification_ref','')).strip()[:180];source=str(p.get('evidence','')).strip()[:1000]
  if not ref or not source:raise ApiError(400,'Payment reference and evidence notes required')
  s=drow(db.execute('SELECT * FROM subscriptions WHERE id=?',(subid,)).fetchone())
  if not s or s['status']!='Pending':raise ApiError(409,'Subscription not pending')
  if db.execute('SELECT 1 FROM subscriptions WHERE verification_ref=?',(ref,)).fetchone():raise ApiError(409,'Payment reference already used')
  db.execute('BEGIN');db.execute('UPDATE subscriptions SET status="Verified",verification_ref=?,paid_at=? WHERE id=?',(ref,now(),subid))
  db.execute('UPDATE contacts SET status="Paid Member / Converted",membership_status="Verified",membership_tier=?,annual_value=?,subscription_date=?,updated_at=? WHERE id=?',(s['tier'],s['amount'],now(),now(),s['contact_id']))
  db.execute('INSERT INTO activity(contact_id,actor,kind,note,verified,created_at) VALUES(?,?,?,?,1,?)',(s['contact_id'],user['username'],'Subscription verified','Evidence: '+source,now()))
  audit(db,user['username'],'subscription.verified',s['contact_id'],{},dict(payment_ref=ref,tier=s['tier']));db.execute('COMMIT');return self.json({'ok':True})
 def audit_list(self,db,user,q):
  auth_role(user,'Administrator');return self.json({'rows':[dict(r) for r in db.execute('SELECT id,actor,action,entity_id,occurred_at FROM audit ORDER BY id DESC LIMIT 250')]})
 def export(self,db,user,q):
  auth_role(user,'Administrator','Sales Manager');where,pars=self.parse_filter(user,q)
  columns=['id','full_name','job_title','company','category','email','phone','country','city','status','owner','eligible_for_outreach','do_not_contact']
  sio=io.StringIO();out=csv.writer(sio);out.writerow(columns)
  for row in db.execute('SELECT '+','.join(columns)+' FROM contacts WHERE '+where+' ORDER BY full_name',pars):
   # CSV formula injection prevention
   out.writerow(["'"+str(x) if isinstance(x,str) and x.startswith(('=','+','-','@','\t','\r')) else x for x in row])
  blob=sio.getvalue().encode('utf-8-sig');self.send_response(200);self.headers_common();self.send_header('Content-Type','text/csv; charset=utf-8');self.send_header('Content-Disposition','attachment; filename="nc_contacts_filtered.csv"');self.send_header('Content-Length',str(len(blob)));self.end_headers();self.wfile.write(blob);audit(db,user['username'],'export.contacts','',{},dict(rows=len(blob)))

if __name__=='__main__':
 if not DB.exists():
  DB.parent.mkdir(parents=True,exist_ok=True)
  schema=(ROOT/'schema_empty.sql').read_text(encoding='utf-8')
  fresh=sqlite3.connect(DB)
  try:fresh.executescript(schema)
  finally:fresh.close()
 ensure();server=ThreadingHTTPServer((HOST,PORT),Handler)
 print(f'N&C Club CRM listening on {HOST}:{PORT} (remote={HOST not in ("localhost","127.0.0.1")})',flush=True)
 server.serve_forever()