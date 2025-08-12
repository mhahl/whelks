import os
import json
import logging
import re
import hashlib
import subprocess
import uuid
from typing import Optional, Tuple, Dict, Any

import redis
import vt
from vt.error import APIError

from processing import utils

# --- Configuration ---
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
REDIS_HOST = os.getenv('REDIS_HOST', '127.0.0.1')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = int(os.getenv('REDIS_DB', 0))
REDIS_USERNAME = os.getenv('REDIS_USERNAME', 'default')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')
TEMP_PATH = os.getenv('TEMP_PATH', '/tmp')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()

# Configure logging once, using a standard format.
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SensorLogProcessor:
    """
    Processes Cowrie events from a Redis queue, scans artifacts,
    and updates a Redis database with intelligence.
    """

    def __init__(self, redis_client: redis.Redis, vt_client: vt.Client):
        """Initializes the processor with necessary clients."""
        if not VT_API_KEY:
            raise ValueError("VIRUSTOTAL_API_KEY environment variable not set.")

        self.redis = redis_client
        self.vt_client = vt_client
        self.ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')

        # Event dispatcher maps event IDs to handler methods.
        self.event_handlers = {
            'cowrie.login.success': self.handle_login_success,
            'cowrie.command.input': self.handle_command_input,
            'cowrie.log.closed': self.handle_log_closed,
            'cowrie.session.file_upload': self.handle_file_upload,
        }

    def scan_file_content(self, file_path: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Scans a file at a given path using VirusTotal.

        Args:
            file_path: The local path to the file to be scanned.

        Returns:
            A tuple containing the file's SHA256 hash and the analysis result as a JSON string.
            Returns (None, None) on failure.
        """
        logger.info(f"Scanning file: {file_path}")
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                shasum = hashlib.sha256(content).hexdigest()

            with open(file_path, "rb") as f:
                # Use a more specific exception handler
                analysis = self.vt_client.scan_file(f, wait_for_completion=True)

            result_json = json.dumps(analysis.to_dict())
            logger.info(f"VirusTotal analysis complete for SHA256: {shasum}")
            return shasum, result_json

        except FileNotFoundError:
            logger.error(f"File not found for scanning: {file_path}")
        except APIError as e:
            logger.error(f"VirusTotal API error while scanning {file_path}: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred during file scan: {e}")
        return None, None

    def scan_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Downloads a file from a URL and scans it.

        Args:
            url: The URL to download and scan.

        Returns:
            A tuple containing the file's SHA256 hash and the analysis result as a JSON string.
        """
        logger.info(f"Scanning URL: {url}")
        clean_url = self.ansi_escape.sub('', url).strip()
        local_path = os.path.join(TEMP_PATH, str(uuid.uuid4()))

        try:
            utils.download_file(clean_url, local_path)
            if os.path.exists(local_path):
                return self.scan_file_content(local_path)
            else:
                logger.warning(f"Failed to download file from URL: {clean_url}")
                return None, None
        finally:
            # Ensure temporary file is always removed
            if os.path.exists(local_path):
                os.remove(local_path)

    def update_url_scan(self, url: str) -> Optional[str]:
        """Scans a URL and saves the results to Redis."""
        shasum, data = self.scan_url(url)
        if not shasum or not data:
            logger.warning(f"Failed to get scan results for URL: {url}")
            return None

        key = f"file:shasum:{shasum}"
        logger.info(f"Saving scan results for {shasum} ({url}) to key: {key}")
        self.redis.set(key, data)
        return shasum

    def handle_login_success(self, event: Dict[str, Any]):
        """Handles cowrie.login.success events."""
        src_ip = event['src_ip']
        self.update_last_seen(src_ip, event['timestamp'])
        self.update_credentials(src_ip, event['username'], event['password'])
        self.perform_nmap_scan(src_ip)

    def handle_command_input(self, event: Dict[str, Any]):
        """Handles cowrie.command.input events."""
        src_ip = event['src_ip']
        session = event['session']
        command = event['input']

        # Store the command
        key = f"ip:{src_ip}:session:{session}:commands"
        logger.info(f"Recording command for session {session}: {command}")
        self.redis.rpush(key, command)

        # Extract and scan any URLs in the command
        urls = utils.extract_download_urls(command)
        if urls:
            url_key = f"ip:{src_ip}:session:{session}:urls"
            for url in urls:
                shasum = self._update_url_scan(url)
                if shasum:
                    self.redis.sadd(url_key, f"{url}:{shasum}")

    def handle_log_closed(self, event: Dict[str, Any]):
        """Handles cowrie.log.closed events to process TTY logs."""
        src_ip, session, tty_hash = event['src_ip'], event['session'], event['shasum']
        key = f"ip:{src_ip}:session:{session}:log"
        logger.info(f"Processing TTY log for session {session} (SHA: {tty_hash})")

        # Use subprocess.run for better control and security vs os.system
        # Assumes the script exists and is executable.
        try:
            source_path = f"static/tty/{tty_hash}"
            dest_path = f"static/tty/{tty_hash}.rec"
            subprocess.run(
                ["python", "scripts/asciinema.py", "-o", dest_path, source_path],
                check=True, capture_output=True, text=True
            )
            self.redis.set(key, tty_hash)
            logger.info(f"Successfully converted TTY log: {tty_hash}")
        except FileNotFoundError:
            logger.error("asciinema.py script not found.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to convert TTY log {tty_hash}: {e.stderr}")

    def handle_file_upload(self, event: Dict[str, Any]):
        """Handles cowrie.session.file_upload events."""
        src_ip, shasum, filename = event['src_ip'], event['shasum'], event['file']
        key = f"ip:{src_ip}:files"
        data = f"{shasum}:{filename}"
        logger.info(f"Recording uploaded file for {src_ip}: {data}")
        self.redis.sadd(key, data)

    # --- Helper Methods for Handlers ---

    def update_last_seen(self, src_ip: str, timestamp: str):
        """Updates the last_updated timestamp for an IP."""
        key = f"ip:{src_ip}:last_updated"
        self.redis.set(key, timestamp)
        logger.info(f"Updated last_seen for {src_ip}")

    def update_credentials(self, src_ip: str, user: str, pword: str):
        """Adds a credential pair to the set for an IP."""
        key = f"ip:{src_ip}:credentials"
        data = f"{user}:{pword}"
        logger.info(f"Storing credentials for {src_ip}")
        self.redis.sadd(key, data)

    def perform_nmap_scan(self, src_ip: str):
        """Performs an Nmap scan if one hasn't been done for this IP."""
        key = f"ip:{src_ip}:scan"
        if self.redis.exists(key):
            logger.info(f"Nmap scan for {src_ip} already exists. Skipping.")
            return

        logger.info(f"Starting Nmap scan for {src_ip}")
        try:
            nmap_args = [
                "nmap", "-sV", "-Pn",
                "--script=ssl-enum-ciphers,banner,vulners,whois-ip",
                src_ip
            ]
            result = subprocess.run(
                nmap_args, capture_output=True, text=True, check=True
            )
            self.redis.set(key, result.stdout)
            logger.info(f"Nmap scan for {src_ip} completed and saved.")
        except FileNotFoundError:
            logger.error("nmap command not found. Please ensure it is installed and in your PATH.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Nmap scan for {src_ip} failed: {e.stderr}")

    def run(self):
        """Starts the main event processing loop."""
        logger.info("Starting Sensor log processor...")
        while True:
            try:
                _, event_data = self.redis.brpop('cowrie')
                event = json.loads(event_data.decode('utf-8'))
                event_id = event.get('eventid')
                logger.debug(f"Received event: {event_id}")

                handler = self.event_handlers.get(event_id)
                if handler:
                    handler(event)
                else:
                    logger.warning(f"No handler found for event: {event_id}")

            except redis.exceptions.ConnectionError as e:
                logger.error(f"Redis connection error: {e}. Retrying...")
                # Consider adding a sleep here to avoid fast reconnection loops
            except json.JSONDecodeError:
                logger.error("Failed to decode JSON from Redis message.")
            except Exception as e:
                logger.critical(f"An unhandled exception occurred in the main loop: {e}", exc_info=True)


def main():
    """
    Main function to initialize clients and start the processor.
    """
    try:
        redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, username=REDIS_USERNAME, password=REDIS_PASSWORD)
        vt_client = vt.Client(VT_API_KEY)

        processor = SensorLogProcessor(redis_client, vt_client)
        processor.run()
    except ValueError as e:
        logger.critical(e)
    except redis.exceptions.ConnectionError as e:
        logger.critical(
            f"Could not connect to Redis at {REDIS_HOST}:{REDIS_PORT}. Please check the connection. Error: {e}")
    except Exception as e:
        logger.critical(f"Failed to initialize the application: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Processor shutting down gracefully.")
