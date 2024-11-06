/**
 * FIDO Metadata Service
 * https://fidoalliance.org/metadata/
 *
 * This file contains functions to parse the downloaded FIDO Metadata Service JWT file.
 */
import fs from 'fs';
import path from 'path';

export interface Algorithm {
  type: 'public-key';
  alg: number;
}

export interface AuthenticatorGetInfo {
  versions: string[];
  extensions: string[];
  aaguid: string;
  options: {
    plat: boolean;
    rk: boolean;
    clientPin: boolean;
    up: boolean;
    credentialMgmtPreview: boolean;
  };
  maxMsgSize: number;
  pinUvAuthProtocols: number[];
  maxCredentialCountInList: number;
  maxCredentialIdLength: number;
  transports: string[];
  algorithms: Algorithm[];
  minPINLength: number;
  firmwareVersion: number;
}

export interface UserVerificationDetail {
  userVerificationMethod: string;
  caDesc?: {
    base: number;
    minLength: number;
    maxRetries: number;
    blockSlowdown: number;
  };
}

export interface MetadataStatement {
  legalHeader: string;
  aaguid: string;
  description: string;
  authenticatorVersion: number;
  protocolFamily: string;
  schema: number;
  upv: Array<{ major: number; minor: number }>;
  authenticationAlgorithms: string[];
  publicKeyAlgAndEncodings: string[];
  attestationTypes: string[];
  userVerificationDetails: UserVerificationDetail[][];
  keyProtection: string[];
  matcherProtection: string[];
  cryptoStrength: number;
  attachmentHint: string[];
  tcDisplay: string[];
  attestationRootCertificates: string[];
  icon: string;
  authenticatorGetInfo: AuthenticatorGetInfo;
}

export interface StatusReport {
  status: string;
  effectiveDate: string;
  certificationDescriptor?: string;
  certificateNumber?: string;
  certificationPolicyVersion?: string;
  certificationRequirementsVersion?: string;
}

export interface FidoMetadataEntry {
  aaguid: string;
  metadataStatement: MetadataStatement;
  statusReports: StatusReport[];
  timeOfLastStatusChange: string;
}

let metadataEntries: FidoMetadataEntry[] = [];

/**
 * Parses a FIDO Metadata Service JWT file into an array of metadata objects
 * @returns The parsed metadata object
 */
export function parseFidoMetadataJWT(): FidoMetadataEntry[] {
  // Read the JWT file
  const jwtPath = path.join(__dirname, '../../data/fido-mds.jwt');
  const jwt = fs.readFileSync(jwtPath, 'utf8');
  const [header, payload, signature] = jwt.split('.');
  const decodedPayload = Buffer.from(payload, 'base64url').toString('utf8');
  const metadata = JSON.parse(decodedPayload);

  // Convert metadata entries to strongly typed MetadataEntry objects
  try {
    const entries: FidoMetadataEntry[] = metadata.entries.map((entry: any) => ({
      aaguid: entry.aaguid,
      metadataStatement: entry.metadataStatement,
      statusReports: entry.statusReports,
      timeOfLastStatusChange: entry.timeOfLastStatusChange,
    }));
    return entries;
  } catch (error) {
    console.error('Error parsing metadata:', error);
    return [];
  }
}

/**
 * Get a FIDO Metadata Service entry by AAGUID
 * @param aaguid - The AAGUID to search for
 * @returns The FIDO Metadata Service entry or undefined if not found
 */
export function getFidoMetadataEntryByAAGUID(aaguid: string): FidoMetadataEntry | undefined {
  return metadataEntries.find(entry => entry.aaguid === aaguid);
}

/**
 * Main function to parse the FIDO Metadata Service JWT file and look up an AAGUID
 */
export function main() {
  metadataEntries = parseFidoMetadataJWT();
  console.log(`Found ${metadataEntries.length} entries`);

  // If AAGUID was provided as command line argument, look it up
  const aaguid = process.argv[2];
  if (aaguid) {
    console.log(`\nLooking up AAGUID: ${aaguid}`);
    const match = getFidoMetadataEntryByAAGUID(aaguid);
    if (match) {
      console.log('\nFound matching authenticator:');
      console.dir(match, { depth: null });
    } else {
      console.log('No matching authenticator found');
    }
  } else {
    console.dir(metadataEntries, { depth: null });
  }
}

metadataEntries = parseFidoMetadataJWT();
