import redis
import json
import subprocess
import logging
import os
import re

# TODO: Get from ENV
r = redis.Redis(host='127.0.0.1', port=6379, db=0)

# Logging
l = logging.getLogger(__name__)

# Get from ENV
logging.basicConfig(level=logging.INFO)

def __extract_download_urls(command_string):
    regex = r"\b(wget|curl)\b.*?((?:https?|ftp)://[^\s'\"]+)"
    matches = re.findall(regex, command_string, re.IGNORECASE)
    urls = [match[1] for match in matches]
    return urls

def update_ip_session_urls(event):
    """
    Update with any detected URLs in the input events.
    """
    src_ip = event['src_ip']
    key = f"ip:{src_ip}:session:{event['session']}:urls"

    urls = __extract_download_urls(f"{event['input']}")
    for url in urls:
        l.info(f"{key}: {url}")
        r.sadd(key, url) 
        

def updated_last_updated(event):
    """
    Ensure the last_updated field is changed.
    """
    src_ip = event['src_ip']
    key_updated = f"ip:{src_ip}:last_updated"
    r.set(key_updated, event['timestamp'])
    l.info(f"last_updated: {src_ip}")

def update_scan(event):
    """
    Update the <ip>:scan key of the database with a scan.
    """
    src_ip = event['src_ip']
    key_scan = f"ip:{src_ip}:scan"


    # Check if we already have scanned the IP in another sessiion
    if r.keys(key_scan):
        l.info(f"{src_ip} already scanned")
        return

    # Kick off an NMAP scan and store the information in the database
    l.info(f"scanning {src_ip}")
    result = subprocess.run(["nmap", "-sV", "-Pn", "--script=ssl-enum-ciphers,banner,vulners,whois-ip", src_ip ], capture_output=True, text=True)

    # Key: src_ip:scan
    r.set(key_scan, result.stdout)

    l.info(f"completed {src_ip}")

def update_credentials(event):
    """
    Update the database with any additional username and password events.
    """

    # get the source ip of the event
    src_ip = event['src_ip']
    
    # get the hash
    key = f"ip:{src_ip}:credentials"
    data = f"{event['username']}:{event['password']}"
    l.info(f"{key}: {data}")
    r.sadd(key, data)



def handle_login_success(event):
    """
    When we have a cowrie.login.success event.
    """
    updated_last_updated(event)
    update_scan(event)
    update_credentials(event)

def handle_command_input(event):
    """
    Update the database with any commands typed into a session.
    """
    src_ip = event['src_ip']
    key = f"ip:{src_ip}:session:{event['session']}:commands"
    data = f"{event['input']}"
    
    update_ip_session_urls(event)

    l.info(f"{key}: {data}")
    r.rpush(key, data) 

def handle_log_closed(event):
    src_ip = event['src_ip']
    key = f"ip:{src_ip}:session:{event['session']}:log"
    l.info(f"{key}: writing tty log")
    recording = event['shasum']

    l.info(f"{key}: converting to ascinemathing")

    # TODO REMOVE
    os.system(f"python scripts/asciinema.py -o static/tty/{event['shasum']}.rec static/tty/{event['shasum']}")

    r.set(key, recording)

def handle_sftp_file_uploaded(event):
    src_ip = event['src_ip']
    key = f"ip:{src_ip}:files"
    data = f"{event['shasum']}:{event['file']}"

    l.info(f"{key}: {data}")
    r.sadd(key, data)


while True:
    metadata = r.brpop('cowrie')
    event = json.loads(metadata[1].decode('utf-8'))

    l.info(f"handling event: {event['eventid']}")


    if event['eventid'] in ('cowrie.login.success'):
        handle_login_success(event)


    if event['eventid'] in ('cowrie.command.input'):
        handle_command_input(event)

    if event['eventid'] in ('cowrie.log.closed'):
        handle_log_closed(event)

    if event['eventid'] in ('cowrie.sftp.file_uploaded'):
        handle_sftp_file_uploaded(event)
