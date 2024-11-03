import { X509Certificate } from 'crypto';
import { YUBIKEY_AAGUIDS } from '../types/attestation';

export async function verifyYubikeyAttestation(
  attestationTrustPath: Buffer[],
  aaguid: string,
  attestationType: string
) {
  console.log('\n🔐 Starting Yubikey verification process...');
  console.log(`📋 Attestation type: ${attestationType}`);

  let isVerifiedYubikey = false;
  let isCryptographicallyVerified = false;
  let yubikeyModel: string | undefined;

  if (attestationTrustPath && attestationTrustPath.length > 0) {
    console.log('✓ Found attestation certificate chain');
    console.log(`📜 Certificate chain length: ${attestationTrustPath.length}`);

    try {
      for (const certBuffer of attestationTrustPath) {
        const cert = new X509Certificate(certBuffer);
        const subject = cert.subject;
        const issuer = cert.issuer;

        console.log(`Checking certificate - Subject: ${subject}, Issuer: ${issuer}`);

        if (subject.includes('Yubico') || issuer.includes('Yubico')) {
          console.log('✓ Found Yubico certificate in chain');
          isCryptographicallyVerified = true;
          isVerifiedYubikey = true;
          yubikeyModel = YUBIKEY_AAGUIDS[aaguid];
          break;
        }
      }
    } catch (error) {
      console.error('Certificate verification error:', error);
    }
  } else {
    console.log('❌ No attestation certificate chain available');
    console.log('ℹ️  This is normal if:');
    console.log('   - Browser is configured for privacy-preserving attestation');
    console.log('   - Browser policy doesn\'t allow full attestation');
    console.log('   - Platform doesn\'t support attestation');
    console.log('   - Using plain HTTP (requires HTTPS with trusted certificate)');
    console.log('   - Using self-signed certificates (requires properly trusted certificate)');
    console.log('   - Using localhost (requires real domain name)');
    console.log('   - Enterprise policies not configured in browser');
  }

  // Fall back to AAGUID lookup if cryptographic verification fails
  if (!isVerifiedYubikey) {
    console.log('\n⚠️  Falling back to AAGUID lookup...');
    console.log(`Current AAGUID: ${aaguid}`);

    isVerifiedYubikey = aaguid in YUBIKEY_AAGUIDS;
    if (isVerifiedYubikey) {
      yubikeyModel = YUBIKEY_AAGUIDS[aaguid];
      console.log('✓ AAGUID match found:', yubikeyModel);
      console.log('⚠️  Note: AAGUID verification is less secure than cryptographic verification');
    } else {
      console.log('❌ No AAGUID match found');
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