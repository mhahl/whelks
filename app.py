import redis
import json
import subprocess
import logging

# TODO: Get from ENV
r = redis.Redis(host='127.0.0.1', port=6379, db=0)

# Logging
l = logging.getLogger(__name__)

# Get from ENV
logging.basicConfig(level=logging.INFO)


def update_session_ip_scan(event):
    
    # Get the source IP of the event
    src_ip = event['src_ip']
    
    # Get the hash
    key = f"{src_ip}:scan"

    # Check if we already have scanned the IP in another sessio
    if r.keys(key):
        l.info(f"{src_ip} already scanned")
        return

    # Kick off an NMAP scan and store the information in the database
    l.info(f"scanning {src_ip}")
    result = subprocess.run(["nmap", "-sV", "-Pn", src_ip ], capture_output=True, text=True)

    # Key: src_ip:scan
    r.set(key, result.stdout)

    l.info(f"completed {src_ip}")

def update_session_timestamp(event):
    pass

def upload_vt():
    pass


while True:
    metadata = r.brpop('cowrie')
    event = json.loads(metadata[1].decode('utf-8'))

    if event['eventid'] in ('cowrie.login.success'):
        l.debug(f"handling event: {event['eventid']}")
        update_session_ip_scan(event)


