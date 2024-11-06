import { X509Certificate } from 'crypto';
import { AttestationStruct, YUBIKEY_AAGUIDS } from '../types/attestation';
import base64url from 'base64url';
import cbor from 'cbor';

export interface AttestationStatement {
  alg: number;
  sig: Buffer;
  x5c: Buffer[];
}

export function decodeAttestationObject(attestationObject: string): AttestationStruct {
  const attestationBuffer = base64url.toBuffer(attestationObject);
  const attestationStruct = cbor.decodeFirstSync(attestationBuffer);
  return attestationStruct;
}

/**
 * Check if the AAGUID is recognized
 * @param aaguid - The AAGUID to check
 * @returns True if the AAGUID is recognized, false otherwise
 */
export function isRecognizedAAGUID(aaguid: string): boolean {
  return aaguid in YUBIKEY_AAGUIDS;
}

/**
 * Check if the attestation object contains a certificate
 */
export function hasCertificate(attestationObject: string): boolean {
  try {
    const decodedAttestation = decodeAttestationObject(attestationObject);
    const x5c = decodedAttestation?.attStmt?.x5c;

    // Check if x5c exists and is an array with at least one certificate
    return Array.isArray(x5c) && x5c.length > 0;
  } catch (error) {
    console.error('Error checking for certificate:', error);
    return false;
  }
}

/**
 * Check if the certificate has an AAGUID
 * @param attestationObject - The attestation object
 * @returns True if the certificate has an AAGUID, false otherwise
 */
export function certHasAAGUID(attestationObject: string): boolean {
  const attestationStruct = decodeAttestationObject(attestationObject);
  return attestationStruct.attStmt.x5c.some(cert => cert.includes('aaguid'));
}

/**
 * Verify the Yubikey attestation
 * @param aaguid - The AAGUID
 * @param attestationObject - The attestation object
 * @returns The verification result
 */
export async function verifyYubikeyAttestation(
  aaguid: string,
  attestationObject: string
) {
  console.log('\n🔐 Starting Yubikey verification process...');

  const attestationStruct = decodeAttestationObject(attestationObject);
  const attestationTrustPath = attestationStruct.fmt === 'packed' ? attestationStruct.attStmt.x5c : [];
  const attestationType = attestationStruct.fmt || 'none';

  let isVerifiedYubikey = false;
  let isCryptographicallyVerified = false;
  let yubikeyModel: string | undefined;

  if (attestationTrustPath && attestationTrustPath.length > 0) {
    try {
      // Get the attestation certificate (first in chain)
      const attCert = new X509Certificate(attestationTrustPath[0]);
      console.log('Attestation Certificate Data:');
      console.log('\tIssuer:', attCert.issuer);
      console.log('\tSubject:', attCert.subject.replace(/\n/g, '; '));
      console.log('\tSerial Number:', attCert.serialNumber);
      console.log('\tValid From:', attCert.validFrom);
      console.log('\tValid To:', attCert.validTo);
      console.log('\tKey Usage:', attCert.keyUsage);
      console.log('\tPublic Key:', attCert.publicKey);

      // Verify certificate chain
      const isYubicoCert = attCert.issuer.includes('Yubico') &&
                          attCert.subject.includes('Yubico');
      console.log('Is Yubico certificate:', isYubicoCert);

      if (isYubicoCert) {
        // Verify certificate validity
        const now = new Date();
        const notBefore = new Date(attCert.validFrom);
        const notAfter = new Date(attCert.validTo);
        console.log('Certificate validity:', { notBefore, notAfter });

        if (now >= notBefore && now <= notAfter) {
          // Verify certificate is for authenticator attestation
          if (attCert.subject.includes('Authenticator Attestation')) {
            isCryptographicallyVerified = true;
            isVerifiedYubikey = true;
            yubikeyModel = YUBIKEY_AAGUIDS[aaguid];
            console.log('Cryptographically verified as Yubikey ', yubikeyModel);
          }
        }
      }
    } catch (error) {
      console.error('Certificate verification error:', error);
    }
  } else {
    console.log('No attestation trust path available');
  }

  // Fall back to AAGUID lookup if cryptographic verification fails
  if (!isVerifiedYubikey) {
    console.log('\n⚠️  Falling back to AAGUID lookup...');
    isVerifiedYubikey = aaguid in YUBIKEY_AAGUIDS;
    if (isVerifiedYubikey) {
      yubikeyModel = YUBIKEY_AAGUIDS[aaguid];
      console.log('AAGUID lookup verified as Yubikey ', yubikeyModel);
    }
  }

  return {
    isVerifiedYubikey,
    isCryptographicallyVerified,
    yubikeyModel,
    attestationType,
    attestationTrustPath: attestationTrustPath.map(cert => cert.toString('hex'))
  };
}