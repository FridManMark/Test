#!/usr/bin/env python3
"""Temporary single-device relay. Bind HTTP only behind a trusted HTTPS reverse proxy.
All data routes require distinct bearer credentials. No shell/file access on relay.
"""
import argparse, hashlib, hmac, json, os, secrets, sqlite3, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ALLOWED = {'status', 'read_script', 'read_logs', 'stage_script', 'command'}
MAX_BODY = 1500000
class State:
    def __init__(self, directory):
        self.directory = Path(directory); self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.operator = os.environ.get('OPERATOR_TOKEN', '')
        if len(self.operator) < 32:
            raise ValueError('Set OPERATOR_TOKEN to at least 32 random ASCII characters')
        self.db = sqlite3.connect(self.directory/'relay.sqlite',check_same_thread=False)
        self.db.execute('CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, session TEXT, expiry REAL, body TEXT, state TEXT, result TEXT)')
        # Never replay uncertain jobs after restarting the relay.
        self.db.execute("UPDATE jobs SET state='unknown_after_restart' WHERE state IN ('queued','delivered')"); self.db.commit()
        self.lock = threading.RLock(); self.device = None; self.last_seen = 0; self.info = {}
        self.new_pair()
        configured = os.environ.get('PAIR_CODE', '')
        if len(configured) < 32:
            raise ValueError('Set PAIR_CODE to at least 32 random ASCII characters')
        self.pair_code = configured
        self.pair_expiry = time.time() + 3600
    def new_pair(self):
        self.pair_code = secrets.token_urlsafe(24); self.pair_expiry = time.time()+1800
        p = self.directory/'pair.json'
        p.write_text(json.dumps({'code':self.pair_code,'expires':self.pair_expiry}));os.chmod(p,0o600)
    def pair(self, code):
        with self.lock:
            if self.device or time.time()>self.pair_expiry or not hmac.compare_digest(str(code).encode(),self.pair_code.encode()):
                raise PermissionError('Pairing unavailable or invalid')
            self.device = {'token':secrets.token_urlsafe(32),'session':str(uuid.uuid4()),'expires':time.time()+3600}
            self.pair_code=''; return self.device.copy()
    def auth(self, bearer, device=False):
        if device:
            return self.device and time.time()<self.device['expires'] and hmac.compare_digest(bearer.encode(),self.device['token'].encode())
        return hmac.compare_digest(bearer.encode(),self.operator.encode())
    def enqueue(self, job):
        with self.lock:
            if not self.device or time.time()>=self.device['expires']:raise ValueError('No live paired session')
            if job.get('op') not in ALLOWED:raise ValueError('Operation denied')
            if job.get('session')!=self.device['session']:raise ValueError('Wrong session')
            if self.db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','delivered')").fetchone()[0]:raise ValueError('One job at a time; resolve pending job first')
            ident=str(uuid.uuid4());expiry=time.time()+min(120,max(5,int(job.get('ttl',60))))
            body=dict(job,id=ident,expires=expiry)
            self.db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,NULL)',(ident,job['session'],expiry,json.dumps(body,ensure_ascii=False),'queued'));self.db.commit()
            return {'id':ident,'state':'queued'}
    def poll(self, info):
        with self.lock:
            self.last_seen=time.time();self.info=info
            self.db.execute("UPDATE jobs SET state='expired' WHERE state='queued' AND expiry<?",(time.time(),))
            r=self.db.execute("SELECT id,body FROM jobs WHERE state='queued' AND session=? ORDER BY rowid LIMIT 1",(self.device['session'],)).fetchone()
            if r:self.db.execute("UPDATE jobs SET state='delivered' WHERE id=?",(r[0],))
            self.db.commit()
            return {'job':json.loads(r[1]) if r else None,'expires':self.device['expires']}
    def result(self, result):
        with self.lock:
            r=self.db.execute('SELECT session,state FROM jobs WHERE id=?',(result.get('id'),)).fetchone()
            if not r or r[0]!=self.device['session']:raise ValueError('Unknown job')
            if r[1]=='delivered':
                self.db.execute('UPDATE jobs SET state=?,result=? WHERE id=?',('answered',json.dumps(result,ensure_ascii=False),result['id']));self.db.commit()
            return {'ok':True}
    def status(self):
        with self.lock:
            session={k:v for k,v in self.device.items() if k!='token'} if self.device else None
            return {'session':session,'last_seen':self.last_seen,'online':bool(session and time.time()<session['expires'] and time.time()-self.last_seen<20),'device':self.info,'jobs':[{'id':r[0],'state':r[1],'result':json.loads(r[2]) if r[2] else None} for r in self.db.execute('SELECT id,state,result FROM jobs ORDER BY rowid DESC LIMIT 20')]}
    def revoke(self):
        with self.lock:
            self.device=None; self.info={};self.db.execute("UPDATE jobs SET state='revoked' WHERE state IN ('queued','delivered')");self.db.commit(); self.new_pair()

class Handler(BaseHTTPRequestHandler):
    server_version='FridManRelay/1'
    def log_message(self,*a):pass
    def reply(self, code, body):
        blob=json.dumps(body,ensure_ascii=False).encode()
        self.send_response(code);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Content-Length',str(len(blob)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(blob)
    def do_GET(self):
        if self.path=='/health':return self.reply(200,{'service':'FridMan relay','version':1})
        if self.path=='/':return self.reply(200,{'service':'FridMan relay','notice':'Private session. Authenticate with the client; no public control panel.'})
        return self.route()
    def do_POST(self):return self.route()
    def route(self):
        with self.server.state.lock:
            return self.locked_route()
    def locked_route(self):
        s=self.server.state
        try:
            self.connection.settimeout(15)
            if self.headers.get('Origin'):return self.reply(403,{'error':'Browser origins not accepted'})
            if self.path=='/v1/pair' and self.command=='POST':
                # High-entropy one-use code; never log bodies or credentials.
                return self.reply(200,s.pair(self.body().get('code','')))
            device=self.path.startswith('/v1/device/')
            token=self.headers.get('Authorization','').removeprefix('Bearer ')
            if not s.auth(token,device):return self.reply(401,{'error':'Unauthorized'})
            if self.path=='/v1/operator/status' and self.command=='GET':return self.reply(200,s.status())
            if self.path=='/v1/operator/job' and self.command=='POST':return self.reply(200,s.enqueue(self.body()))
            if self.path=='/v1/operator/revoke' and self.command=='POST':s.revoke();return self.reply(200,{'ok':True})
            if self.path=='/v1/device/poll' and self.command=='POST':return self.reply(200,s.poll(self.body()))
            if self.path=='/v1/device/result' and self.command=='POST':return self.reply(200,s.result(self.body()))
            return self.reply(404,{'error':'Not found'})
        except PermissionError:return self.reply(403,{'error':'Pairing rejected'})
        except (ValueError,KeyError,TypeError):return self.reply(400,{'error':'Invalid request or busy'})
        except Exception:return self.reply(500,{'error':'Internal error'})
    def body(self):
        n=int(self.headers.get('Content-Length','0'))
        if n<0 or n>MAX_BODY:raise ValueError('Size limit')
        b=json.loads(self.rfile.read(n));
        if not isinstance(b,dict):raise ValueError('Object required')
        return b

def main():
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=int(os.environ.get('PORT', '10000')));p.add_argument('--state',default=os.environ.get('STATE_DIR', '/tmp/fridman-relay'));a=p.parse_args()
    server=ThreadingHTTPServer(('0.0.0.0',a.port),Handler);server.state=State(a.state)
    print('Relay listening. No device connected. Free hosting restarts reset sessions.',flush=True);server.serve_forever()
if __name__=='__main__':main()
