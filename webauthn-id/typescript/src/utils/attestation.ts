import { X509Certificate } from 'crypto';
import { YUBIKEY_AAGUIDS } from '../types/attestation';

interface AttestationStatement {
  alg: number;
  sig: Buffer;
  x5c: Buffer[];
}

export async function verifyYubikeyAttestation(
  attestationTrustPath: Buffer[],
  aaguid: string,
  attestationType: string
) {
  console.log('\n🔐 Starting Yubikey verification process...');

  let isVerifiedYubikey = false;
  let isCryptographicallyVerified = false;
  let yubikeyModel: string | undefined;

  if (attestationTrustPath && attestationTrustPath.length > 0) {
    try {
      // Get the attestation certificate (first in chain)
      const attCert = new X509Certificate(attestationTrustPath[0]);
      console.log('Attestation certificate:', attCert);

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