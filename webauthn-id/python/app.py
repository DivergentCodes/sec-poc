#!/usr/bin/env python3

from flask import Flask, render_template, jsonify, request, session
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
)
from webauthn.helpers.structs import (
    RegistrationCredential,
    AuthenticationCredential,
    UserVerificationRequirement,
    AuthenticatorSelectionCriteria,
)
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass
from config import get_config
import os

# Initialize app with config
config = get_config()
app = Flask(__name__)
app.secret_key = config['FLASK_SECRET']

# In-memory storage - replace with database in production
users = {}
credentials = {}

# Update these values for your environment
ENVIRONMENT = config['ENVIRONMENT']
RENDER_EXTERNAL_HOSTNAME = config['RENDER_EXTERNAL_HOSTNAME']
RP_ID = config['RP_ID']
RP_NAME = config['RP_NAME']
ORIGIN = config['ORIGIN']  # Change back to http://

# Add these constants at the top
YUBICO_ROOT_CERT_URL = "https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt"
YUBICO_AAGUID_URL = "https://raw.githubusercontent.com/Yubico/python-fido2/master/examples/yubico_aaguids.py"

YUBIKEY_AAGUIDS = {
    "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5 NFC",
    "fa2b99dc-9e39-4257-8f92-4a30d23c4118": "YubiKey 5Ci",
    "2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 Nano",
    "73bb0cd4-e502-49b8-9c6f-b59445bf720b": "YubiKey 5C",
    "c1f9a0bc-1dd2-404a-b27f-8e29047a43fd": "YubiKey 5C Nano",
    "f8a011f3-8c0a-4d15-8006-17111f9edc7d": "Security Key by Yubico",
    "b92c3f9a-c014-4056-887f-140a2501163b": "Security Key 2 (NFC)",
    "6d44ba9b-f6ec-2e49-b930-0c8fe920cb73": "Security Key NFC",
    "149a0017-fc0d-44f4-8436-071f80f10c06": "YubiKey Bio",
    "4c42b904-1a9c-4f3a-8bdb-6b1f104534db": "YubiKey Bio FIPS",
    "7c0903ab-b1a0-464b-8653-8ba19bc4aa49": "YubiKey 5C FIPS",
    "b305321d-867f-4838-9c38-3d5845775582": "YubiKey 5Ci FIPS",
    "cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5 FIPS",
    "c5ef55ff-ad9a-4b9f-b580-adebafe026d0": "YubiKey 5 NFC FIPS",
}

print("RegistrationCredential structure:", dir(RegistrationCredential))
print("RegistrationCredential fields:", [field for field in RegistrationCredential.__dataclass_fields__])

@dataclass
class RegistrationResponse:
    client_data_json: bytes
    attestation_object: bytes

@app.route('/')
def index():
    return render_template('index.html',
                         credentials=credentials.values(),
                         rp_id=RP_ID,
                         rp_name=RP_NAME,
                         environment=ENVIRONMENT,
                         render_external_hostname=RENDER_EXTERNAL_HOSTNAME)

@app.route('/register', methods=['GET'])
def register_begin():
    user_id = str(uuid.uuid4()).encode('utf-8')
    user_name = "test_user"

    options = generate_registration_options(
        rp_id=config['RP_ID'],
        rp_name=config['RP_NAME'],
        user_id=user_id,
        user_name=user_name,
        user_display_name=user_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment="cross-platform"
        ),
        attestation="direct"  # Explicitly request direct attestation
    )

    session['current_registration_challenge'] = options.challenge

    # Convert to dictionary and handle bytes encoding
    options_dict = {
        "publicKey": {
            "rp": options.rp,
            "user": {
                "id": bytes_to_base64url(options.user.id),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "challenge": bytes_to_base64url(options.challenge),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],  # ES256
            "timeout": 60000,  # 60 seconds
            "attestation": "direct",  # Request full attestation
            "authenticatorSelection": {
                "userVerification": "preferred",
                "authenticatorAttachment": "cross-platform"
            }
        }
    }

    return jsonify(options_dict)

def fetch_yubico_root_certs():
    """Fetch and parse Yubico's root certificates."""
    response = requests.get(YUBICO_ROOT_CERT_URL)
    certs = []
    current_cert = []

    for line in response.text.split('\n'):
        if '-----BEGIN CERTIFICATE-----' in line:
            current_cert = [line]
        elif '-----END CERTIFICATE-----' in line:
            current_cert.append(line)
            cert_str = '\n'.join(current_cert)
            certs.append(x509.load_pem_x509_certificate(cert_str.encode()))
        elif current_cert:
            current_cert.append(line)

    return certs

def verify_yubikey_attestation(attestation_cert_chain):
    """Verify that the attestation certificate chain is from Yubico."""
    try:
        print("\nStarting Yubikey cryptographic verification...")

        if not attestation_cert_chain:
            print("❌ No attestation certificate chain provided")
            return False

        print(f"📜 Found {len(attestation_cert_chain)} certificates in chain")

        # Convert attestation certs from DER to X509
        attestation_certs = [
            load_der_x509_certificate(cert)
            for cert in attestation_cert_chain
        ]

        # Fetch Yubico root certificates
        print("🌐 Fetching Yubico root certificates...")
        root_certs = fetch_yubico_root_certs()
        print(f"✓ Found {len(root_certs)} Yubico root certificates")

        # Verify certificate chain
        print("\nVerifying certificate chain...")
        for i, cert in enumerate(attestation_certs[:-1]):
            print(f"\nVerifying certificate {i + 1}/{len(attestation_certs)}")
            print(f"Subject: {cert.subject}")
            issuer = attestation_certs[i + 1]
            print(f"Issuer: {issuer.subject}")

            # Verify certificate signature
            issuer_public_key = issuer.public_key()
            try:
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_algorithm_parameters
                )
                print("✓ Signature verified")
            except Exception as e:
                print(f"❌ Certificate signature verification failed: {e}")
                return False

            # Verify certificate is not expired
            now = datetime.now(timezone.UTC)
            print(f"Validity period: {cert.not_valid_before} to {cert.not_valid_after}")
            if cert.not_valid_before > now or cert.not_valid_after < now:
                print("❌ Certificate is expired or not yet valid")
                return False
            print("✓ Certificate dates valid")

        # Verify root certificate is from Yubico
        root_cert = attestation_certs[-1]
        print("\nVerifying root certificate...")
        print(f"Root cert subject: {root_cert.subject}")

        is_yubico_root = any(
            root_cert.subject == yubico_root.subject
            for yubico_root in root_certs
        )

        if is_yubico_root:
            print("✓ Root certificate verified as genuine Yubico root")
        else:
            print("❌ Root certificate not recognized as Yubico root")

        return is_yubico_root

    except Exception as e:
        print(f"❌ Attestation verification failed: {e}")
        return False

@app.route('/register', methods=['POST'])
def register_complete():
    challenge = session['current_registration_challenge']

    try:
        # Parse the incoming JSON data
        registration_data = request.get_json()

        # Create the response object
        response = RegistrationResponse(
            client_data_json=base64url_to_bytes(registration_data['response']['clientDataJSON']),
            attestation_object=base64url_to_bytes(registration_data['response']['attestationObject'])
        )

        # Create RegistrationCredential object
        credential = RegistrationCredential(
            id=registration_data['id'],
            raw_id=base64url_to_bytes(registration_data['rawId']),
            response=response,
            type=registration_data['type'],
            authenticator_attachment=None
        )

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )

        # Handle AAGUID - just use it directly if it's already a string
        if isinstance(verification.aaguid, str):
            aaguid = verification.aaguid
        else:
            try:
                aaguid = str(uuid.UUID(bytes=verification.aaguid))
            except Exception as e:
                print(f"AAGUID conversion error: {e}")
                print(f"Raw AAGUID: {verification.aaguid}")
                aaguid = verification.aaguid.hex() if hasattr(verification.aaguid, 'hex') else str(verification.aaguid)

        print("\n🔐 Starting Yubikey verification process...")

        # Get attestation information
        attestation_type = getattr(verification, 'attestation_type', 'none')
        attestation_trust_path = getattr(verification, 'attestation_trust_path', [])

        print(f"📋 Attestation type: {attestation_type}")
        print(f"🔍 Checking for attestation certificate chain...")

        # Verify Yubikey attestation if available
        is_verified_yubikey = False
        is_cryptographically_verified = False
        yubikey_model = None

        # First try cryptographic verification
        if attestation_trust_path:
            print("✓ Found attestation certificate chain")
            print(f"📜 Certificate chain length: {len(attestation_trust_path)}")
            print("\n🔒 Attempting cryptographic verification...")
            is_cryptographically_verified = verify_yubikey_attestation(attestation_trust_path)
            if is_cryptographically_verified:
                is_verified_yubikey = True
                yubikey_model = YUBIKEY_AAGUIDS.get(aaguid)
                print("✅ Cryptographic verification successful!")
        else:
            print("❌ No attestation certificate chain available")
            print("ℹ️  This is normal if:")
            print("   - Browser is configured for privacy-preserving attestation")
            print("   - Browser policy doesn't allow full attestation")
            print("   - Platform doesn't support attestation")
            print("   - Using plain HTTP (requires HTTPS with trusted certificate)")
            print("   - Using self-signed certificates (requires properly trusted certificate)")
            print("   - Using localhost (requires real domain name)")
            print("   - Enterprise policies not configured in browser")

            print("\n⚠️  Falling back to AAGUID lookup...")
            print(f"Current AAGUID: {aaguid}")
            is_verified_yubikey = aaguid in YUBIKEY_AAGUIDS
            yubikey_model = YUBIKEY_AAGUIDS.get(aaguid) if is_verified_yubikey else None
            print(f"AAGUID lookup result: {'✓ Match found' if is_verified_yubikey else '❌ No match'}")
            if is_verified_yubikey:
                print("⚠️  Note: AAGUID verification is less secure than cryptographic verification")
                print("   AAGUID can be spoofed by malicious authenticators")

        # Add debug logging
        print("\n📊 Final Verification Results:")
        print(f"AAGUID: {aaguid}")
        print(f"Attestation type: {attestation_type}")
        print(f"Trust path length: {len(attestation_trust_path)}")
        print(f"Is Verified Yubikey: {is_verified_yubikey}")
        print(f"Verification method: {'Cryptographic' if is_cryptographically_verified else 'AAGUID lookup' if is_verified_yubikey else 'None'}")
        if yubikey_model:
            print(f"Yubikey Model: {yubikey_model}")

        new_credential = {
            'id': bytes_to_base64url(verification.credential_id),
            'public_key': bytes_to_base64url(verification.credential_public_key),
            'aaguid': aaguid,
            'sign_count': verification.sign_count,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'attestation_type': attestation_type,
            'attestation_trust_path': [cert.hex() if isinstance(cert, bytes) else str(cert)
                                     for cert in attestation_trust_path],
            'backup_eligible': getattr(verification, 'backup_eligible', None),
            'backup_state': getattr(verification, 'backup_state', None),
            'user_verified': getattr(verification, 'user_verified', None),
            'user_present': getattr(verification, 'user_present', None),
            'is_verified_yubikey': is_verified_yubikey,
            'is_cryptographically_verified': is_cryptographically_verified,
            'verification_method': 'cryptographic' if is_cryptographically_verified else 'aaguid_lookup' if is_verified_yubikey else 'none',
            'yubikey_model': yubikey_model,
            'credential_type': credential.type
        }

        credentials[new_credential['id']] = new_credential

        return jsonify({
            'status': 'success',
            'aaguid': aaguid,
            'sign_count': verification.sign_count,
            'is_verified_yubikey': is_verified_yubikey,
            'is_cryptographically_verified': is_cryptographically_verified,
            'yubikey_model': yubikey_model
        })

    except Exception as e:
        print(f"Registration error: {str(e)}")
        print(f"Registration data: {registration_data}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 400

@dataclass
class AuthenticationResponse:
    authenticator_data: bytes
    client_data_json: bytes
    signature: bytes

@app.route('/authenticate', methods=['GET'])
def authenticate_begin():
    if not credentials:
        return jsonify({'error': 'No credentials registered'}), 400

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[{"type": "public-key", "id": base64url_to_bytes(cred_id)}
                         for cred_id in credentials.keys()],
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    session['current_authentication_challenge'] = options.challenge

    # Convert the options to a JSON-serializable dictionary
    options_dict = {
        "challenge": bytes_to_base64url(options.challenge),
        "timeout": options.timeout,
        "rpId": options.rp_id,
        "allowCredentials": [
            {
                "type": "public-key",
                "id": cred_id  # credentials.keys() are already base64url strings
            }
            for cred_id in credentials.keys()
        ],
        "userVerification": options.user_verification
    }

    return jsonify(options_dict)

@app.route('/authenticate', methods=['POST'])
def authenticate_complete():
    challenge = session['current_authentication_challenge']
    auth_data = None  # Initialize this before the try block

    try:
        # Parse the incoming JSON data
        auth_data = request.get_json()
        if not auth_data:
            return jsonify({'error': 'No JSON data received'}), 400

        # Create AuthenticationCredential object
        credential = AuthenticationCredential(
            id=auth_data['id'],
            raw_id=base64url_to_bytes(auth_data['rawId']),
            response=AuthenticationResponse(
                authenticator_data=base64url_to_bytes(auth_data['response']['authenticatorData']),
                client_data_json=base64url_to_bytes(auth_data['response']['clientDataJSON']),
                signature=base64url_to_bytes(auth_data['response']['signature'])
            ),
            type=auth_data['type']
        )

        credential_id = bytes_to_base64url(credential.raw_id)
        stored_credential = credentials.get(credential_id)

        if not stored_credential:
            return jsonify({'error': 'Credential not found'}), 400

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=base64url_to_bytes(stored_credential['public_key']),
            credential_current_sign_count=stored_credential['sign_count']
        )

        # Update sign count
        credentials[credential_id]['sign_count'] = verification.new_sign_count

        # Get more details from the authentication data
        auth_data_details = {
            'status': 'success',
            'aaguid': stored_credential['aaguid'],
            'sign_count': verification.new_sign_count,
            'previous_sign_count': stored_credential['sign_count'],
            'credential_id': credential_id,
            'backup_state': getattr(verification, 'backup_state', None),
            'backup_eligible': getattr(verification, 'backup_eligible', None),
            'user_verified': getattr(verification, 'user_verified', None),
            'user_present': getattr(verification, 'user_present', None),
            'authentication_time': datetime.now(timezone.utc).isoformat(),
        }

        # Update credential with latest data
        credentials[credential_id].update({
            'sign_count': verification.new_sign_count,
            'last_used': datetime.now(timezone.utc).isoformat(),
            'user_verified': auth_data_details['user_verified'],
            'user_present': auth_data_details['user_present'],
        })

        return jsonify(auth_data_details)

    except Exception as e:
        print(f"Authentication error: {str(e)}")  # Debug log
        if auth_data:  # Only print auth_data if it exists
            print(f"Authentication data: {auth_data}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 400

@app.route('/credentials/<credential_id>', methods=['DELETE'])
def delete_credential(credential_id):
    if credential_id in credentials:
        del credentials[credential_id]
        return jsonify({'status': 'success'})
    return jsonify({'error': 'Credential not found'}), 404

@app.route('/.well-known/webauthn', methods=['GET'])
def webauthn_config():
    return jsonify({
        "version": 1,
        "registrationPolicies": ["none"],
        "supportedAuthenticatorAttachment": ["platform", "cross-platform"]
    }), 200, {'Content-Type': 'application/json'}

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000)) # Default on Render
    app.run(host='0.0.0.0', port=port)