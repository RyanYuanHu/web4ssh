#!/usr/bin/python3

import os, sys, json, uuid, paramiko, socket, base64, time
from copy import deepcopy 
from functools import reduce
from threading import Timer
from multiprocessing import Process

from flask import request, Response, Flask

app = Flask(__name__)
apilist = {}
currTimer = ""

err_success        = [200, {"resultcode":"0", "message":"success"}]
err_badrequest     = [400, {"resultcode": "-1", "message":"invalid request"}]
err_authentication = [200, {"resultcode": "-1", "message":"authentication failure"}]
err_connection     = [200, {"resultcode": "-1", "message":"connection failed"}]
err_socketerror    = [200, {"resultcode": "-1", "message":"socket error"}]
err_connoverlimit  = [200, {"resultcode": "-1", "message":"connection over limit"}]
err_notfound       = [404, {"resultcode": "-1", "message":"api not found"}]

sessions = {}
# {'sid' : $sid, 
#  'conn': {
#     '$connidx': {'username':$username, 'password': $password, 'ip':$ip, 'port':$port, 'client':$client, 'channel':$channel},
#      ...
#   }
# }

exitSign = False

############################################
def api(name, **options):
    def decorator(f):
        apilist[name] = f
        return f
    return decorator

#############################################
# /v1/rest/abc
#############################################
@api("abc")
def api_abc():
    for s in request.args:
        print(s + ":" + request.args[s])
    return err_success

    
#############################################
# /v1/rest/disconnect?connid=connid
# connid: htmlEncode
# cookie.sid: raw
#############################################
@api("disconnect")
def api_disconnect():
    if 'sid' not in request.cookies or 'connid' not in request.args:
        return err_badrequest
    
    # get parameters from request
    sid = request.cookies['sid']
    connid=request.args['connid']
    
    # check whether sid is valid
    if sid not in sessions:
        return err_badrequest
     
    # get session records
    s = sessions[sid]
    
    # check whether connid is valid
    if connid not in s:
        return err_badrequest
    
    # now close items
    s[connid]['channel'].close()
    s[connid]['client'].close()
    
    # delete it from the chain
    del s[connid]
    print("conn closed:", connid)
    
    return err_success


#############################################
# /v1/rest/connect?usr=username&pwd=password&host=ip&port=port
# username: htmlEncode
# password: htmlEncode
# ip: htmlEncode
# port: htmlEncode
# cookie.sid: raw
#############################################
@api("connect")
def api_connect():
    if 'sid' not in request.cookies or 'usr' not in request.args or 'pwd' not in request.args or 'host' not in request.args:
        return err_badrequest

    sid = request.cookies['sid']
    if sid not in sessions:
        sessions[sid]={}
    elif len(sessions[sid]) >= 5:
        return err_connoverlimit
    
    # get parameters for connection
    username = request.args['usr']
    password = request.args['pwd']
    ip       = request.args['host']
    port     = 22
    if 'port' in request.args:
        port = request.args['port']
    
    password = base64.b64decode(password.encode('utf-8')).decode('utf-8')
    
    # start connection
    client = paramiko.SSHClient()
    # client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(ip, port=port, username=username, password=password)
    except paramiko.AuthenticationException:   #  if authentication failed
        return err_authentication
    except paramiko.SSHException:              #  if there was any other error connecting or establishing a SSH session
        return err_connection
    except socket.error:                       #  if a socket error occurred while connecting
        return err_socketerror
        
    chan = client.invoke_shell()
    chan.settimeout(0.0)
    
    # create a dict for the new connection
    s = {}
    s['username']  = username
    s['password']  = password
    s['ip']        = ip
    s['port']      = port
    s['client']    = client
    s['channel']   = chan
    s['lastcheck'] = time.time()
    
    # generate a new connection id
    connid = uuid.uuid4().hex
    # save it in sessions
    sessions[sid][connid] = s
    
    ret = deepcopy(err_success)
    ret[1]['connid'] = connid
    
    return ret
    
@api("check")
def api_check():
    if 'sid' not in request.cookies or 'connid' not in request.args:
        return err_badrequest
    
    sid = request.cookies['sid']
    connid = request.args['connid']
    
    if sid not in sessions:
        return err_badrequest

    sess = sessions[sid]
    if connid not in sess:
        return err_badrequest
    
    conn = sess[connid]
    
    if 'client' not in conn or 'channel' not in conn:
        return err_badrequest
    
    conn['lastcheck'] = time.time()
    
    client = conn['client']
    chan   = conn['channel']

    if 'keys' in request.args:
        keys = request.args['keys']
        keys = eval('[' + keys + ']')
        # convert each item in keys from keycode to char and link them to a string
        keys = reduce(lambda x, y: x + y, list(map(chr, keys)))
        
        print("keys=", keys)
        try:
            chan.send(keys)
        except (socket.timeout, socket.error) as e:
            chan.close()
            client.close()
            ret = deepcopy(err_socketerror)
            ret[1]['closed'] = 1
            del sess[connid]
            print(e)
            print("conn closed:", connid)
            return ret
    
    closed = False
    over = False
    
    ret_str = ""
    
    while not closed and not over:
        try:
            out_str = chan.recv(1024)
            if len(out_str) == 0:
                closed = True
            else:
                ret_str += out_str.decode('utf-8')
        except socket.timeout:
            out_str = b""
            over = True

    ret = deepcopy(err_success)
    # the content might contain special chars. encode them with base64 before put into json
    ret[1]['content'] = base64.b64encode(ret_str.encode()).decode('utf-8')
    
    if closed:
        ret[1]['closed'] = 1
        sess[connid]['channel'].close()
        sess[connid]['client'].close()
        del sess[connid]
        print("conn closed:", connid)
    
    return ret

#####################################################
def cleanduefiles(path, timegate):
    for root, dirs, files in os.walk(path):
        for fn in files:
            fullpath = root + '/' + fn
            if os.stat(fullpath).st_mtime <= timegate:
                os.remove(fullpath)
                print("deleted: ", fullpath)
            
#####################################################
def timerprocess():
    print("in timer...")
    TIMEOUT = 300
    timegate = time.time() - TIMEOUT
    
    # check all sessions
    for sid in list(sessions):
        sess = sessions[sid]
        for connid in list(sess):
            if sess[connid]['lastcheck'] < timegate:
                sess[connid]['channel'].close()
                sess[connid]['client'].close()
                del sess[connid]
                print("idle conn closed. session: ", sid, ", connid:", connid)

    FILE_CLEAN_DURATION = 3600 * 3
    timegate = time.time() - FILE_CLEAN_DURATION
    cleanduefiles('./tmp', timegate)
    cleanduefiles('./static/tmp', timegate)
    
    global currTimer
    
    if not exitSign:
        currTimer = Timer(10.0, timerprocess)
        currTimer.start()

#####################################################
def construct_response(ret):
    r = Response(response=json.dumps(ret[1]), status=ret[0])
    r.headers["Content-Type"] = "application/json; charset=utf-8"
    return r
    

#####################################################
@app.route("/v1/rest/<apiname>")
def restapi(apiname):
    if apiname in apilist:
        r = apilist[apiname]()
    else:
        r = err_notfound
    
    return construct_response(r)

#####################################################
# /v1/download?path=path&usr=username&pwd=password&host=ip&port=port
#####################################################
@app.route("/v1/download")
def download_file():
    if 'path' not in request.args or 'usr' not in request.args or 'pwd' not in request.args or 'host' not in request.args:
        return construct_response(err_badrequest)

    remotepath = request.args['path']
    username   = request.args['usr']
    password   = request.args['pwd']
    ip         = request.args['host']
    port       = 22
    
    if 'port' in request.args:
        port = request.args['port']

    password = base64.b64decode(password.encode('utf-8')).decode('utf-8')

    transport = paramiko.Transport(ip, port)
    transport.connect(username = username, password = password)
    sftp = paramiko.SFTPClient.from_transport(transport, window_size=paramiko.common.DEFAULT_WINDOW_SIZE, max_packet_size=paramiko.common.DEFAULT_MAX_PACKET_SIZE)
    
    localname = uuid.uuid4().hex
    localpath = './static/tmp/' + localname
    sftp.get(remotepath, localpath)
    # close
    sftp.close()
    transport.close()
    
    return app.send_static_file('./tmp/' + localname)

#####################################################
# /v1/upload/create
#####################################################
@app.route("/v1/upload/create")
def upload_create():
    ret = deepcopy(err_success)
    ret[1]['fid'] = uuid.uuid4().hex
    return construct_response(ret)

#####################################################
# /v1/upload/transport?fid=fid&pos=pos&len=len&content=content
#####################################################
@app.route("/v1/upload/transport")
def upload_transport():
    if 'fid' not in request.args or 'pos' not in request.args or 'len' not in request.args or 'content' not in request.args:
        return construct_response(err_badrequest)

    fid = request.args['fid']
    p   = request.args['pos']
    l   = request.args['len']
    c   = request.args['content']
    
    try:
        l = int(l)
        p = int(p)
    except ValueError:
        return construct_response(err_badrequest)

    if l != len(c):
        print("len inequal")
        return construct_response(err_badrequest)
    
    filepath = './tmp/' + fid
    
    with open(filepath, 'ab') as fd:
        fd.write(c.encode('utf-8'))
    
    r = deepcopy(err_success)
    r[1]['len'] = os.stat(filepath).st_size
    
    return construct_response(r)

#####################################################
# /v1/upload/submit?fid=fid&path=path&usr=username&pwd=password&host=ip&port=port
#####################################################
@app.route("/v1/upload/submit")
def upload_submit():
    if 'fid' not in request.args or 'path' not in request.args or 'usr' not in request.args or 'pwd' not in request.args or 'host' not in request.args:
        return construct_response(err_badrequest)

    fid        = request.args['fid']
    remotepath = request.args['path']
    username   = request.args['usr']
    password   = request.args['pwd']
    ip         = request.args['host']
    port       = 22
    if 'port' in request.args:
        port = request.args['port']
    
    password = base64.b64decode(password.encode('utf-8')).decode('utf-8')
    
    transport = paramiko.Transport(ip, port)
    transport.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(transport, window_size=paramiko.common.DEFAULT_WINDOW_SIZE, max_packet_size=paramiko.common.DEFAULT_MAX_PACKET_SIZE)
    
    # upload
    localpath = './tmp/' + fid
    print("localpath=", localpath)
    print("remotepath=", remotepath)
    
    sftp.put(localpath, remotepath)
    sftp.close()
    transport.close()
    
    r = deepcopy(err_success)
    r[1]['len'] = os.stat(localpath).st_size
    return construct_response(r)
    
@app.route('/exit')
def exitserver():
    shutdown_server()
    return "server shutting down..."

@app.route('/')
def rootdir():
    return srv_servepage("index.html")

@app.route('/<path:path>')
def hello_world(path):
    return srv_servepage(path)

def srv_servepage(path):
    resp = app.make_response(app.send_static_file(path))
    if "sid" not in request.cookies:
        resp.set_cookie("sid", uuid.uuid4().hex)
    else:
        sss = request.cookies['sid']
        print("sid=", sss)
    return resp
    
def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug server')
    
    global currTimer
    currTimer.cancel()
    global exitSign
    exitSign = True
    func()
    
def runproc():
    print("child process id:", os.getpid())
    global currTimer
    currTimer = Timer(10.0, timerprocess)
    currTimer.start()
    app.run(host='0.0.0.0', port=7736)

# main entry here
if __name__ == "__main__":
    print("main proc pid:", os.getpid())
    p = Process(target=runproc)
    print("child process created")
    p.start()
    print("child process started")
    p.join()
    print("main proc ended")
