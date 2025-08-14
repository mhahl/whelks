import os
import json
import redis
import geocoder

from flask_cors import cross_origin
from flask import Flask, render_template, request

# --- Configuration ---
# Load configuration from environment variables for security and flexibility.
REDIS_HOST = os.getenv('REDIS_HOST', '127.0.0.1')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = int(os.getenv('REDIS_DB', 0))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)


class SensorDB:
    """
    A Data Access Layer for interacting with the honeypot data in Redis.
    This class encapsulates all Redis queries.
    """

    def __init__(self, redis_client):
        self.r = redis_client

    def get_sessions_for_ip(self, ip: str) -> list:
        """Helper to get session IDs for an IP. Still uses KEYS but is now isolated."""
        # Note: This still uses KEYS, which is not ideal. A better schema would
        # maintain a Set of session IDs for each IP.
        #ip:203.174.143.46:session:7bc26a71ebd3:commands
        session_keys = self.r.keys(f"ip:{ip}:session:*:log")
        return [key.split(':')[3] for key in session_keys]

    def get_all_ips(self) -> list:
        """
        Gets all unique IP addresses from a dedicated index.
        This avoids the dangerous 'KEYS' command on the entire database.

        NOTE: Your data ingestion script must be modified to add each new IP to this set:
        `r.sadd("index:ips", new_ip)`
        """
        return sorted(list(self.r.smembers("index:ips")))

    def get_ip_summary_data(self, ip: str) -> dict:
        """Fetches lightweight summary data for the main IP list view."""
        # Use SCARD for efficient counting
        session_count = len(self.get_sessions_for_ip(ip))
        files_count = self.r.scard(f"ip:{ip}:files")

        # To count URLs, we must iterate through session URL sets
        url_count = 0
        sessions = self.get_sessions_for_ip(ip)
        if sessions:
            url_keys = [f"ip:{ip}:session:{s}:urls" for s in sessions]
            # Use SUNION to get all unique URLs across all sessions for this IP
            url_count = len(self.r.sunion(url_keys))

        return {
            "ip": ip,
            "last_updated": self.r.get(f"ip:{ip}:last_updated"),
            #"location": geocoder.ip(ip).city,
            "location": "none",
            "session_count": session_count,
            "files_count": files_count,
            "url_count": url_count
        }

    def get_ip_details(self, ip: str) -> dict:
        """Fetches all detailed information for a single IP address."""
        sessions_data = []
        session_ids = self.get_sessions_for_ip(ip)

        ip_url_count = 0

        for session_id in session_ids:
            data = {
                "id": session_id,
                "commands": self.r.lrange(f"ip:{ip}:session:{session_id}:commands", 0, -1),
                "log_shasum": self.r.get(f"ip:{ip}:session:{session_id}:log"),
                "urls": self.r.smembers(f"ip:{ip}:session:{session_id}:urls"),
            }
            ip_url_count += len(data['urls'])
            sessions_data.append(data)

        return {
            "ip": ip,
            "scan": self.r.get(f"ip:{ip}:scan"),
            "credentials": self.r.smembers(f"ip:{ip}:credentials"),
            "files": self.r.smembers(f"ip:{ip}:files"),
            "sessions": sessions_data,
            "location": geocoder.ip(ip),
            "url_count": ip_url_count
        }

    def get_file_report(self, shasum: str) -> dict:
        """Retrieves and decodes a file analysis report."""
        report_json = self.r.get(f"file:shasum:{shasum}")
        if report_json:
            return json.loads(report_json)
        return {}


# --- Flask Application ---

def create_app():
    """Application factory to create and configure the Flask app."""
    app = Flask(__name__)
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        decode_responses=True
    )
    db = SensorDB(redis_client)

    @app.route('/')
    @cross_origin()
    def list_ips():
        """Displays a list of all tracked IPs with summary data."""
        all_ips = db.get_all_ips()
        # Fetch summary data for each IP
        ip_summaries = [db.get_ip_summary_data(ip) for ip in all_ips]
        return render_template('ip_list.html', ip_summaries=ip_summaries)

    @app.route('/ip/<ip>')
    @cross_origin()
    def show_ip(ip):
        """Displays detailed information for a specific IP."""
        # Fetch all details in one go and pass the data dictionary to the template
        details = db.get_ip_details(ip)
        print(details)
        return render_template('ip_show.html', details=details)

    @app.route('/files/<shasum>/results')
    @cross_origin()
    def file_show_results(shasum):
        """Displays the analysis results for a specific file hash."""
        filename = request.args.get('filename', 'N/A')
        report = db.get_file_report(shasum)
        print(report)
        return render_template('file_show_results.html',
                               filename=filename,
                               report=report,
                               shasum=shasum)

    return app


if __name__ == '__main__':
    app = create_app()
    # Use debug=False in a production environment
    app.run(debug=True)
