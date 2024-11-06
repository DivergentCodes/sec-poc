import { CredentialDeviceType, AuthenticatorTransportFuture } from '@simplewebauthn/types';

import { AuthenticatorChecks } from './authenticator';
import { CertificateChainValidationResult } from '../utils/certificate-validation';
import { FidoMetadataEntry } from '../utils/fido-mds';
import { RecognizedAAGUID } from './types';

export type UserModel = {
  id: any;
  name: string;
};

export const theUser: UserModel = {
  id: 'test-user',
  name: 'test@example.com',
};

export type AuthenticatorModel = {
  status: string;
  credentialID: Base64URLString;
  credentialPublicKey: Base64URLString;
  aaguid: string;
  signCount: number;
  previousSignCount: number;
  backupState: boolean;
  backupEligible: boolean;
  userVerified: boolean;
  created: string;
  lastUsed: string;

  // SQL: Store raw bytes as `BYTEA`/`BLOB`/etc...
  //      Caution: Node ORM's may map this to a Buffer on retrieval,
  //      convert to Uint8Array as necessary
  publicKey: Uint8Array;

  // SQL: Foreign Key to an instance of your internal user model
  user: UserModel;

  // SQL: Store as `TEXT`. Index this column. A UNIQUE constraint on
  //      (webAuthnUserID + user) also achieves maximum user privacy
  webauthnUserID: Base64URLString;

  // SQL: Consider `BIGINT` since some authenticators return atomic timestamps as counters
  counter: number;
  // SQL: `VARCHAR(32)` or similar, longest possible value is currently 12 characters
  // Ex: 'singleDevice' | 'multiDevice'

  deviceType: CredentialDeviceType;
  // SQL: `BOOL` or whatever similar type is supported
  backedUp: boolean;
  // SQL: `VARCHAR(255)` and store string array as a CSV string
  // Ex: ['ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb']
  transports?: AuthenticatorTransportFuture[];

  isVerifiedYubikey?: boolean;
  isCryptographicallyVerified?: boolean;
  yubikeyModel?: string;
  attestationType?: string;
  attestationTrustPath?: string[];
  verificationMethod?: string;

  recognizedAAGUID?: RecognizedAAGUID;
  fidoMetadata?: FidoMetadataEntry;
  certChainValidation?: CertificateChainValidationResult;
  fidoRootCertValidation?: CertificateChainValidationResult;

  authenticatorChecks: AuthenticatorChecks;
};