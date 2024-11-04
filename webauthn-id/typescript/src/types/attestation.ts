import { AttestationStatement } from "../utils/attestation";

export interface VerificationResult {
  isVerifiedYubikey: boolean;
  isCryptographicallyVerified: boolean;
  yubikeyModel?: string;
  attestationType: string;
  attestationTrustPath?: string[];
}

export type AttestationStruct = {
  attStmt: AttestationStatement;
  fmt: string;
}

export const YUBIKEY_AAGUIDS: Record<string, string> = {
  'ee882879-721c-4913-9775-3dfcce97072a': 'YubiKey 5 NFC',
  'fa2b99dc-9e39-4257-8f92-4a30d23c4118': 'YubiKey 5Ci',
  '2fc0579f-8113-47ea-b116-bb5a8db9202a': 'YubiKey 5 Nano',
  '73bb0cd4-e502-49b8-9c6f-b59445bf720b': 'YubiKey 5C',
  'c1f9a0bc-1dd2-404a-b27f-8e29047a43fd': 'YubiKey 5C Nano',
  'f8a011f3-8c0a-4d15-8006-17111f9edc7d': 'Security Key by Yubico',
  'b92c3f9a-c014-4056-887f-140a2501163b': 'Security Key 2 (NFC)',
  '6d44ba9b-f6ec-2e49-b930-0c8fe920cb73': 'Security Key NFC',
  '149a0017-fc0d-44f4-8436-071f80f10c06': 'YubiKey Bio',
  '4c42b904-1a9c-4f3a-8bdb-6b1f104534db': 'YubiKey Bio FIPS'
};