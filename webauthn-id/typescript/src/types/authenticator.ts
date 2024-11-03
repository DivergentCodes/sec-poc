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
    isVerifiedYubikey?: boolean;
    isCryptographicallyVerified?: boolean;
    yubikeyModel?: string;
    attestationType?: string;
    attestationTrustPath?: string[];
}