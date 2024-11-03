import os
from typing import TypedDict

class Config(TypedDict):
    RP_ID: str
    RP_NAME: str
    ORIGIN: str
    FLASK_SECRET: str

def get_config() -> Config:
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
    custom_domain = os.getenv('CUSTOM_DOMAIN')
    host = custom_domain or render_host or 'localhost'

    return {
        'RP_ID': host,
        'RP_NAME': os.getenv('RP_NAME', 'WebAuthn Demo'),
        'ORIGIN': f"https://{host}",
        'FLASK_SECRET': os.getenv('FLASK_SECRET', 'change-me-in-production')
    }