"""test Flask with this"""

import redis
import geocoder

from flask import Flask , render_template
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


@app.route('/')
def list_ips():
    return render_template('ip_list.html', ips=get_ips(), geocoder=geocoder, get_last_updated_for_ip=get_last_updated_for_ip)
    
@app.route('/ip/<ip>')
def show_ip(ip):
    scan = r.get(f"ip:{ip}:scan")
    sessions = get_sessions_for_ip(ip)
    return render_template('ip_show.html', 
                           sessions=sessions, 
                           scan=scan, 
                           ip=ip,
                           geocoder=geocoder,
                           get_commands_for_session=get_commands_for_session,
                           get_log_for_ip_session=get_log_for_ip_session,
                           get_credentials_for_ip=get_credentials_for_ip
                           )

