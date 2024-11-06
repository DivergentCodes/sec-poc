import crypto from 'crypto';
import { generateAuthenticationOptions, GenerateAuthenticationOptionsOpts, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { AuthenticatorModel } from '../types/models';

/**
 * Generate authentication options for an authenticator
 * @param rpID - The RP ID
 * @param authenticators - The authenticators
 * @returns The authentication options
 */
export async function keyAuthenticationRequest(
  rpID: string,
  authenticators: Map<string, AuthenticatorModel>
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  console.log('Authenticators registered:', authenticators.size);
  if (authenticators.size === 0) {
    throw new Error('No authenticators registered yet');
  }

  const userAuthenticators = Array.from(authenticators.values());
  const genOptions: GenerateAuthenticationOptionsOpts = {
    rpID,
    allowCredentials: userAuthenticators.map(authenticator => ({
      id: authenticator.credentialID,
      transports: authenticator.transports,
      type: 'public-key',
    })),
    challenge: Buffer.from(crypto.randomBytes(32)),
    userVerification: 'preferred',
  }
  const options = await generateAuthenticationOptions(genOptions);

  console.log('Authentication options:');
  console.dir(options, { depth: null });
  return options;
}

/**
 * Verify the authentication response from an authenticator
 * @param body - The authentication response
 * @param challenge - The challenge
 * @param origin - The origin
 * @param rpID - The RP ID
 * @param authenticator - The authenticator
 * @returns The authenticator
 */
export async function keyAuthenticationVerification(
  body: any,
  challenge: string,
  origin: string,
  rpID: string,
  authenticator: AuthenticatorModel
): Promise<AuthenticatorModel> {
  const verificationParams = {
    response: body,
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    requireUserVerification: true,
    credential: {
      id: authenticator.credentialID,
      publicKey: Buffer.from(authenticator.credentialPublicKey, 'base64url'),
      counter: authenticator.counter,
    },
  };

  console.log('Authentication verification parameters:');
  console.dir(verificationParams, { depth: null });

  const verificationResult = await verifyAuthenticationResponse(verificationParams);
  console.log('Authentication verification result:');
  console.dir(verificationResult, { depth: null });

  const { verified, authenticationInfo } = verificationResult;

  if (!verified) {
    throw new Error('Authentication verification failed');
  }

  console.log('Authentication successful, updating authenticator data');

  // Update authenticator data
  authenticator.previousSignCount = authenticator.counter;
  authenticator.counter = authenticationInfo.newCounter;
  authenticator.userVerified = authenticationInfo.userVerified;
  authenticator.deviceType = authenticationInfo.credentialDeviceType;
  authenticator.backedUp = authenticationInfo.credentialBackedUp;

  authenticator.lastUsed = new Date().toISOString();

  console.log('Authentication details:');
  console.dir(authenticator, { depth: null });

  return authenticator;
}