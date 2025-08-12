import re
import requests
import logging

from botocore.exceptions import ClientError
from botocore.session import get_session

# Logging
log = logging.getLogger(__name__)

def extract_download_urls(command_string):
    """
    Extract download urls from a command string.
    """
    regex = r"\b(wget|curl)\b.*?((?:https?|ftp)://[^\s'\"]+)"
    matches = re.findall(regex, command_string, re.IGNORECASE)
    urls = [match[1] for match in matches]
    return urls

def download_file(url, save_path):
    """
    Download a file from a URL.
    """
    try:
        response = requests.get(url, stream=True) # Use stream=True for large files
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        with open(save_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192): # Iterate over content in chunks
                file.write(chunk)
        log.info(f"file saved for upload {url} -> {save_path}")
    except requests.exceptions.RequestException as e:
        log.info(f"error: {e}")