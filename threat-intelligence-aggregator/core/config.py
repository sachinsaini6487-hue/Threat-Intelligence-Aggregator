import os
from dotenv import load_dotenv

def load_config():
    load_dotenv()
    return {
        "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
        "ABUSEIPDB_API_KEY": os.getenv("ABUSEIPDB_API_KEY", "").strip(),
        "OTX_API_KEY": os.getenv("OTX_API_KEY", "").strip(),
    }
