
import redis
import geocoder
import json

from flask import Flask , render_template, request
app = Flask(__name__)

r = redis.Redis(host='127.0.0.1', port=6379, db=0)


def get_ips():
    return map(lambda x: x.decode().split(':')[1], r.keys("ip:*:scan"))

def get_sessions_for_ip(ip):
    return map(lambda x: x.decode().split(':')[3], r.keys(f"ip:{ip}:session:*:log"))

def get_commands_for_session(ip, session):
    return r.lrange(f"ip:{ip}:session:{session}:commands",0, -1)

def get_last_updated_for_ip(ip):
    return r.get(f"ip:{ip}:last_updated").decode()

def get_log_for_ip_session(ip, session):
    return r.get(f"ip:{ip}:session:{session}:log").decode()

def get_credentials_for_ip(ip):
    return r.smembers(f"ip:{ip}:credentials")

def get_files_for_ip(ip):
    return r.smembers(f"ip:{ip}:files")

def get_urls_for_ip_session(ip,session):
    print(r.smembers(f"ip:{ip}:session:{session}:urls"))
    return r.smembers(f"ip:{ip}:session:{session}:urls")


def get_urls_count_for_ip(ip):
    count = 0
    sessions = get_sessions_for_ip(ip)
    for session in sessions:
        count += len(list(r.smembers(f"ip:{ip}:session:{session}:urls")))
    return count

#127.0.0.1:6379> keys *urls
#1) "ip:103.214.222.109:session:b8b18458dfd3:urls"
#2) "ip:103.214.222.109:session:8f2850c2f475:urls"
#3) "ip:103.214.222.109:session:494754263da9:urls"
#4) "ip:103.214.222.109:session:184817b21428:urls"


def get_urls_count_for_ip_session(ip,session):
    return len(list(r.smembers(f"ip:{ip}:session:{session}:urls")))

def get_files_count_for_ip(ip):
    return len(list(r.smembers(f"ip:{ip}:files")))

def get_session_count_for_ip(ip):
    return len(list(map(lambda x: x.decode().split(':')[3], r.keys(f"ip:{ip}:session:*:log"))))

@app.route('/files/<shasum>/results')
def file_show_results(shasum):
    filename = request.args.get('filename')
    report = json.loads(r.get(f"file:shasum:{shasum}").decode())
    return render_template('file_show_results.html',
                           filename=filename,
                           report=report,
                           shasum=shasum)

@app.route('/')
def list_ips():
    return render_template('ip_list.html',
                           ips=get_ips(),
                           geocoder=geocoder,
                           get_last_updated_for_ip=get_last_updated_for_ip,
                           get_files_count_for_ip=get_files_count_for_ip,
                           get_session_count_for_ip=get_session_count_for_ip,
                           get_urls_for_ip_session=get_urls_for_ip_session,
                           get_urls_count_for_ip_session=get_urls_count_for_ip_session,
                           get_urls_count_for_ip=get_urls_count_for_ip)
    
@app.route('/ip/<ip>')
def show_ip(ip):
    scan = r.get(f"ip:{ip}:scan")
    sessions = list(get_sessions_for_ip(ip))
    return render_template('ip_show.html', 
                           sessions=sessions, 
                           scan=scan, 
                           ip=ip,
                           geocoder=geocoder,
                           get_commands_for_session=get_commands_for_session,
                           get_log_for_ip_session=get_log_for_ip_session,
                           get_credentials_for_ip=get_credentials_for_ip,
                           get_files_for_ip=get_files_for_ip,
                           get_files_count_for_ip=get_files_count_for_ip,
                           get_urls_count_for_ip_session=get_urls_count_for_ip_session,
                           get_urls_for_ip_session=get_urls_for_ip_session,
                           get_urls_count_for_ip=get_urls_count_for_ip
                           )

