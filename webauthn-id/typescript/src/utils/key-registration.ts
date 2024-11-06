import { AuthenticatorModel, UserModel } from '../types/models';
import { verifyRegistrationResponse, generateRegistrationOptions, GenerateRegistrationOptionsOpts, VerifyRegistrationResponseOpts } from '@simplewebauthn/server';
import base64url from 'base64url';
import { certHasAAGUID, decodeAttestationObject, hasCertificate, isRecognizedAAGUID, verifyYubikeyAttestation } from './attestation';
import { getFidoMetadataEntryByAAGUID } from './fido-mds';
import crypto from 'crypto';
import { AuthenticatorChecks } from '../types/authenticator';
import { CertificateChainValidationResult, validateAuthenticatorCertificate, validateCertificateChain, validateFIDOCertificateChain } from './certificate-validation';
import { lookupRecognizedAAGUID } from './aaguid-lists';

/**
 * Generate registration options for the browser to pass to a supported authenticator.
 * These options recommend configurations for the authenticator to use and generate
 * a challenge for the authenticator to sign.
 *
 * @param rpName - The RP name
 * @param rpID - The RP ID
 * @param user - The user
 * @returns The registration options
 */
export async function keyRegistrationRequest(
  rpName: string,
  rpID: string,
  user: UserModel
) {
  // TODO: fine-tune residentKey, userVerification, authenticatorAttachment
  const genOptions: GenerateRegistrationOptionsOpts = {
    rpName,
    rpID,
    userID: Buffer.from(user.id),
    userName: user.name,
    challenge: Buffer.from(crypto.randomBytes(32)),
    attestationType: 'direct',
    authenticatorSelection: {
      userVerification: 'preferred',
      authenticatorAttachment: 'cross-platform',
    }
  }
  const options = await generateRegistrationOptions(genOptions);

  console.log('Registration options generated:', {
    rpName,
    rpID,
    userId: user.id,
    userName: user.name,
    challengeLength: options.challenge.length,
  });

  return options;
}

/**
 * Verify the registration response from an authenticator by checking:
 * - The response matches the original challenge sent to the client
 * - The origin matches the expected origin
 * - The RP ID matches the expected RP ID
 * - The attestation is valid (if present)
 * - The credential public key is properly formatted
 * - The authenticator data is properly signed
 *
 * @param body - The registration response containing attestation and client data
 * @param challenge - The original challenge that was sent to the client
 * @param origin - The expected origin of the request
 * @param rpID - The expected Relying Party ID
 * @param user - The user registering the authenticator
 * @returns The verified authenticator model with credential details
 */
export async function handleKeyRegistrationVerification(
  body: any,
  challenge: string,
  origin: string,
  rpID: string,
  user: UserModel
): Promise<AuthenticatorModel> {
  const verificationParams: VerifyRegistrationResponseOpts = {
    response: body,
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
  }

  // This is the verification provided by the simplewebauthn library.
  const verification = await verifyRegistrationResponse(verificationParams);
  const { verified, registrationInfo } = verification;
  if (!verified || !registrationInfo) {
    throw new Error('Registration verification failed');
  }

  const { aaguid, credential, credentialDeviceType, credentialBackedUp } = registrationInfo;
  const { id: credentialID, publicKey: credentialPublicKey, counter } = credential;
  let certChainValidation: CertificateChainValidationResult | undefined = undefined;
  let fidoRootCertValidation: CertificateChainValidationResult | undefined = undefined;
  const authenticatorChecks: AuthenticatorChecks = {
    recognizedAAGUID: false,
    fidoMdsAAGUID: false,
    certPresent: false,
    certHasAAGUID: false,
    certValid: false,
    certChainValid: false,
    fidoRootCertValid: false,
  };

  const recognizedAAGUID = lookupRecognizedAAGUID(aaguid);
  authenticatorChecks.recognizedAAGUID = !!recognizedAAGUID;

  if (authenticatorChecks.recognizedAAGUID) {
    console.log('✅ AAGUID is recognized:', aaguid);
  } else {
    console.error('❌ AAGUID is not recognized:', aaguid);
  }

  const fidoMetadata = getFidoMetadataEntryByAAGUID(aaguid);
  if (fidoMetadata) {
    console.log('✅ FIDO Metadata found for AAGUID:', aaguid);
    authenticatorChecks.fidoMdsAAGUID = true;
  } else {
    console.error('❌ FIDO Metadata not found for AAGUID:', aaguid);
  }

  authenticatorChecks.certPresent = hasCertificate(body.response.attestationObject);
  if (authenticatorChecks.certPresent) {
    console.log('✅ Certificate is present');
  } else {
    console.error('❌ Certificate is not present');
  }

  if (authenticatorChecks.certPresent) {
    const certValidation = validateAuthenticatorCertificate(body.response.attestationObject);
    if (certValidation.isValid) {
      console.log('✅ Certificate is valid');
      authenticatorChecks.certValid = true;
    } else {
      console.error('❌ Certificate is not valid:', certValidation.error);
    }

    certChainValidation = validateCertificateChain(body.response.attestationObject);
    if (certChainValidation?.isValid) {
      console.log('✅ Certificate chain is valid');
      authenticatorChecks.certChainValid = true;
    } else {
      console.error('❌ Certificate chain is not valid:', certChainValidation.error);
    }

    if (fidoMetadata) {
      fidoRootCertValidation = validateFIDOCertificateChain(body.response.attestationObject, fidoMetadata);
      if (fidoRootCertValidation?.isValid) {
        console.log('✅ Certificate chain verified against FIDO trusted root');
        authenticatorChecks.fidoRootCertValid = true;
      } else {
        console.error('❌ Certificate chain does not match FIDO trusted root:', fidoRootCertValidation?.error);
      }
    }
  }

  const authenticator: AuthenticatorModel = {
    status: 'success',
    credentialID,
    credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
    aaguid,

    signCount: counter,
    previousSignCount: 0,

    backupState: credentialBackedUp,
    backupEligible: credentialBackedUp,
    userVerified: false,

    created: new Date().toISOString(),
    lastUsed: new Date().toISOString(),

    user: {
      id: user.id,
      name: user.name,
    },

    webauthnUserID: user.id,
    publicKey: credentialPublicKey,
    counter,

    transports: credential.transports,
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,

    recognizedAAGUID,
    fidoMetadata,
    certChainValidation,
    fidoRootCertValidation,

    authenticatorChecks,
  };

  return authenticator;
}
