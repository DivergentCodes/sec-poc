import { X509Certificate } from 'crypto';
import base64url from 'base64url';
import cbor from 'cbor';
import { FidoMetadataEntry } from './fido-mds';

export interface CertificateChainValidationResult {
  isValid: boolean;
  chainDetails: {
    depth: number;
    certificates: Array<{
      subject: string;
      issuer: string;
      validFrom: Date;
      validTo: Date;
      serialNumber: string;
      isSelfSigned: boolean;
    }>;
  };
  error?: string;
}

export interface CertificateValidationResult {
  isValid: boolean;
  details: {
    subject: string;
    issuer: string;
    validFrom: Date;
    validTo: Date;
    serialNumber: string;
    isExpired: boolean;
    isNotYetValid: boolean;
  };
  error?: string;
}

/**
 * Validate a single authenticator certificate without chain validation
 * @param attestationObject - The attestation object
 * @returns The certificate validation result
 */
export function validateAuthenticatorCertificate(attestationObject: string): CertificateValidationResult {
  try {
    // Extract the leaf certificate
    const certChain = extractCertChain(attestationObject);
    if (!certChain.length) {
      throw new Error('No certificates found in attestation object');
    }

    // Parse the leaf certificate
    const cert = new X509Certificate(certChain[0]);
    const now = new Date();
    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);

    // Check temporal validity
    const isExpired = now > validTo;
    const isNotYetValid = now < validFrom;
    const isValid = !isExpired && !isNotYetValid;

    return {
      isValid,
      details: {
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom,
        validTo,
        serialNumber: cert.serialNumber,
        isExpired,
        isNotYetValid
      }
    };
  } catch (error) {
    return {
      isValid: false,
      details: {
        subject: '',
        issuer: '',
        validFrom: new Date(0),
        validTo: new Date(0),
        serialNumber: '',
        isExpired: true,
        isNotYetValid: true
      },
      error: error instanceof Error ? error.message : 'Unknown error parsing certificate'
    };
  }
}

/**
 * Extract certificate chain from attestation object
 */
function extractCertChain(attestationObject: string): Buffer[] {
  try {
    const attestationBuffer = base64url.toBuffer(attestationObject);
    const attestationStruct = cbor.decodeFirstSync(attestationBuffer);

    if (!attestationStruct.attStmt?.x5c || !Array.isArray(attestationStruct.attStmt.x5c)) {
      throw new Error('No certificate chain found in attestation statement');
    }

    return attestationStruct.attStmt.x5c;
  } catch (error) {
    throw new Error(`Failed to extract certificate chain: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Validate the certificate chain without checking trusted roots.
 * The authenticator's leaf certificate's signature can be verified using the root's public key.
 */
export function validateCertificateChain(attestationObject: string): CertificateChainValidationResult {
  try {
    const certChain = extractCertChain(attestationObject);

    if (!certChain.length) {
      return {
        isValid: false,
        chainDetails: { depth: 0, certificates: [] },
        error: 'Empty certificate chain'
      };
    }

    const certificates = certChain.map(cert => new X509Certificate(cert));
    const now = new Date();
    const chainDetails: CertificateChainValidationResult['chainDetails'] = {
      depth: certificates.length,
      certificates: []
    };

    // Validate each certificate's temporal validity
    for (const cert of certificates) {
      const validFrom = new Date(cert.validFrom);
      const validTo = new Date(cert.validTo);

      if (now < validFrom || now > validTo) {
        return {
          isValid: false,
          chainDetails,
          error: `Certificate ${cert.subject} is not temporally valid`
        };
      }

      const isSelfSigned = cert.subject === cert.issuer;
      chainDetails.certificates.push({
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom,
        validTo,
        serialNumber: cert.serialNumber,
        isSelfSigned
      });
    }

    // Validate certificate chain linkage
    for (let i = 0; i < certificates.length - 1; i++) {
      const current = certificates[i];
      const issuer = certificates[i + 1];

      if (current.issuer !== issuer.subject) {
        return {
          isValid: false,
          chainDetails,
          error: `Certificate chain broken between ${current.subject} and ${issuer.subject}`
        };
      }

      try {
        const verified = current.verify(issuer.publicKey);
        if (!verified) {
          return {
            isValid: false,
            chainDetails,
            error: `Invalid signature in chain at depth ${i}`
          };
        }
      } catch (error) {
        return {
          isValid: false,
          chainDetails,
          error: `Signature verification failed at depth ${i}: ${error instanceof Error ? error.message : 'Unknown error'}`
        };
      }
    }

    return {
      isValid: true,
      chainDetails
    };
  } catch (error) {
    return {
      isValid: false,
      chainDetails: { depth: 0, certificates: [] },
      error: error instanceof Error ? error.message : 'Unknown error validating certificate chain'
    };
  }
}

/**
 * Validate the certificate chain against FIDO metadata root certificates
 */
export function validateFIDOCertificateChain(
  attestationObject: string,
  fidoMdsEntry: FidoMetadataEntry
): CertificateChainValidationResult {
  try {
    // First perform basic chain validation
    const basicValidation = validateCertificateChain(attestationObject);
    if (!basicValidation.isValid) {
      return basicValidation;
    }

    // Get the leaf certificate
    const certChain = extractCertChain(attestationObject);
    const leafCert = new X509Certificate(certChain[0]);

    // Convert FIDO root certificates
    const fidoMdsRootCerts = fidoMdsEntry.metadataStatement.attestationRootCertificates;
    const fidoTrustedRoots = fidoMdsRootCerts.map(cert => {
      // The FIDO MDS certificates are in standard base64
      const certBuffer = Buffer.from(cert, 'base64');
      return new X509Certificate(certBuffer);
    });

    // Find a root cert that matches the leaf cert's issuer
    const matchingRoot = fidoTrustedRoots.find(rootCert =>
      leafCert.issuer === rootCert.subject
    );

    if (!matchingRoot) {
      return {
        isValid: false,
        chainDetails: basicValidation.chainDetails,
        error: 'No matching root certificate found in FIDO metadata roots'
      };
    }

    // Verify the leaf certificate is signed by the root
    try {
      const verified = leafCert.verify(matchingRoot.publicKey);
      if (!verified) {
        return {
          isValid: false,
          chainDetails: basicValidation.chainDetails,
          error: 'Leaf certificate signature verification failed'
        };
      }
    } catch (error) {
      return {
        isValid: false,
        chainDetails: basicValidation.chainDetails,
        error: `Signature verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }

    return basicValidation;
  } catch (error) {
    return {
      isValid: false,
      chainDetails: { depth: 0, certificates: [] },
      error: error instanceof Error ? error.message : 'Unknown error validating FIDO certificate chain'
    };
  }
}