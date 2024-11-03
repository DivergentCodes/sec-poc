import os
from typing import TypedDict
from pprint import pprint
from urllib.parse import urlparse

class Config(TypedDict):
    RP_ID: str
    RP_NAME: str
    ORIGIN: str
    FLASK_SECRET: str

def get_config() -> Config:
    pprint(os.environ)

    environment = os.getenv('FLASK_ENV', 'development')

    if environment == 'development':
        return {
            'RP_ID': 'localhost',
            'RP_NAME': 'WebAuthn Demo (Dev)',
            'ORIGIN': 'http://localhost:5000',
            'FLASK_SECRET': 'dev-secret-key'
        }

    # Production settings (Render)
    render_host = os.getenv('RENDER_EXTERNAL_HOSTNAME')
    if not render_host:
        raise ValueError('RENDER_EXTERNAL_HOSTNAME environment variable is required in production')

    # Extract the onrender.com domain
    if '.onrender.com' in render_host:
        domain = 'onrender.com'  # Use the top-level domain for RP_ID
    else:
        domain = render_host

    return {
        'RP_ID': domain,
        'RP_NAME': os.getenv('RP_NAME', 'WebAuthn Demo'),
        'ORIGIN': f"https://{render_host}",  # Full hostname for origin
        'FLASK_SECRET': os.getenv('FLASK_SECRET', 'change-me-in-production')
    }