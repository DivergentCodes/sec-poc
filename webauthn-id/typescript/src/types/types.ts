import { VerifiedRegistrationResponse, VerifiedAuthenticationResponse } from '@simplewebauthn/server';

export interface Authenticator {
    credentialID: string;
    credentialPublicKey: string;
    counter: number;
    aaguid: string;
    created: string;
    lastUsed?: string;
    credentialType: string;
    backupEligible?: boolean;
    backupState?: boolean;
    userVerified?: boolean;
    userPresent?: boolean;
}

export interface AuthenticationDetails {
    status: 'success';
    aaguid: string;
    signCount: number;
    previousSignCount: number;
    credentialId: string;
    backupState?: boolean;
    backupEligible?: boolean;
    userVerified?: boolean;
    userPresent?: boolean;
    authenticationTime: string;
}

export interface RecognizedAAGUID {
  aaguid: string;
  name: string;
  icon?: string;
  authenticatorVersion?: number;
  description?: string;
  website?: string;
}
