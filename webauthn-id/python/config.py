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
    if not render_host:
        raise ValueError('RENDER_EXTERNAL_HOSTNAME environment variable is required in production')

    return {
        'RP_ID': render_host,  # Use the full Render hostname
        'RP_NAME': os.getenv('RP_NAME', 'WebAuthn Demo'),
        'ORIGIN': f"https://{render_host}",  # Always use HTTPS in production
        'FLASK_SECRET': os.getenv('FLASK_SECRET', 'change-me-in-production')
    }