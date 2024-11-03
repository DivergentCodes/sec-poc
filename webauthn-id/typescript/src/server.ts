import express from 'express';
import session from 'express-session';
import path from 'path';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { AuthenticatorTransportFuture, CredentialDeviceType } from '@simplewebauthn/types';
import crypto from 'crypto';
import { verifyYubikeyAttestation } from './utils/attestation';

declare module 'express-session' {
  interface SessionData {
    challenge: string;
  }
}

type UserModel = {
  id: any;
  name: string;
};

const theUser: UserModel = {
  id: 'test-user',
  name: 'test@example.com',
};

type AuthenticatorModel = {
  status: string;
  credentialID: Base64URLString;
  credentialPublicKey: Base64URLString;
  aaguid: string;
  signCount: number;
  previousSignCount: number;
  backupState: boolean;
  backupEligible: boolean;
  userVerified: boolean;
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
};

interface AuthenticationDetails {
  status: string;
  aaguid: string;
  signCount: number;
  previousSignCount: number;
  credentialId: string;
  backupState: boolean;
  backupEligible: boolean;
  userVerified: boolean;
  authenticationTime: string;
}

const app = express();
const port = process.env.PORT || 3000;

// In-memory storage - replace with database in production
const users: Map<string, UserModel> = new Map();
const authenticators: Map<string, AuthenticatorModel> = new Map();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secure-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

// Config
const rpId = process.env.RP_ID || 'localhost';
const rpName = process.env.RP_NAME || 'WebAuthn TypeScript Demo';
const origin = process.env.ORIGIN || `http://${rpId}:${port}`;

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/**
 * Handles the registration request
 * @param req - The request object
 * @param res - The response object
 */
app.get('/register', async (req, res) => {
  console.log('Starting registration process...');

  console.log(`Generating registration options for user: ${theUser.name}`);
  const options = await generateRegistrationOptions({
    rpName,
    rpID: rpId,
    userID: Buffer.from(theUser.id),
    userName: theUser.name,
    challenge: Buffer.from(crypto.randomBytes(32)),
    attestationType: 'direct',
    authenticatorSelection: {
      userVerification: 'preferred',
      authenticatorAttachment: 'cross-platform',
    }
  });

  console.log('Registration options generated:', {
    rpName,
    rpID: rpId,
    userId: theUser.id,
    userName: theUser.name,
    challengeLength: options.challenge.length,
  });

  req.session.challenge = options.challenge;
  console.log('Challenge stored in session');

  req.session.save((err) => {
    if (err) {
      console.error('Failed to save session:', err);
      res.status(500).json({ status: 'error', message: 'Failed to save session' });
      return;
    }
    console.log('Session saved successfully, sending options to client');
    res.json(options);
  });
});

/**
 * Handles the registration verification request
 * @param req - The request object
 * @param res - The response object
 */
app.post('/register', async (req, res) => {
  console.log('Received registration verification request');
  const { body } = req;

  try {
    if (!req.session.challenge) {
      console.error('No challenge found in session');
      throw new Error('Missing challenge in session');
    }

    console.log('Verifying registration response...');
    console.log('Expected origin:', origin);
    console.log('Expected RPID:', rpId);

    // Verify the registration response
    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: req.session.challenge,
      expectedOrigin: origin,
      expectedRPID: rpId,
    });

    const { verified, registrationInfo } = verification;
    console.log('Registration verification result:', { verified });

    if (!verified || !registrationInfo) {
      console.error('Registration verification failed');
      throw new Error('Registration verification failed');
    }

    const { id: credentialID, publicKey: credentialPublicKey, counter } = registrationInfo.credential;
    const { aaguid } = registrationInfo;

    const attestationTrustPath = (registrationInfo.attestationObject as any)?.fmt === 'packed'
      ? (registrationInfo.attestationObject as any)?.attStmt?.x5c || []
      : [];
    const attestationType = (registrationInfo.attestationObject as any)?.fmt || 'none';

    const attestationResult = await verifyYubikeyAttestation(
      attestationTrustPath,
      aaguid,
      attestationType,
    );

    // Store the new authenticator in the database
    // const newAuthenticator = {
    //   credentialID: Buffer.from(credentialID).toString('base64url'),
    //   credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
    //   counter,
    //   aaguid,
    //   created: new Date().toISOString(),
    // };
    const {
      credential,
      credentialDeviceType,
      credentialBackedUp,
    } = registrationInfo;

    const authenticator: AuthenticatorModel = {
      status: 'success',
      // A unique identifier for the credential
      credentialID,
      credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
      aaguid,
      signCount: counter,
      previousSignCount: 0,
      backupState: credentialBackedUp,
      backupEligible: credentialBackedUp,
      userVerified: false,
      lastUsed: new Date().toISOString(),

      // `user` here is from Step 2
      user: {
        id: theUser.id,
        name: theUser.name,
      },

      // Created by `generateRegistrationOptions()` in Step 1
      webauthnUserID: theUser.id,

      // The public key bytes, used for subsequent authentication signature verification
      publicKey: credentialPublicKey,

      // The number of times the authenticator has been used on this site so far
      counter,

      // How the browser can talk with this credential's authenticator
      transports: credential.transports,
      // Whether the passkey is single-device or multi-device
      deviceType: credentialDeviceType,
      // Whether the passkey has been backed up in some way
      backedUp: credentialBackedUp,

      ...attestationResult,
    };
    authenticators.set(authenticator.credentialID, authenticator);
    console.log('Saved authenticator:', authenticator);

    // Send the new authenticator details to the client
    res.json({
      status: 'success',
      authenticator: authenticator,
    });
  } catch (error: any) {
    console.error('Registration error:', error);
    console.error('Error stack:', error.stack);
    res.status(400).json({ status: 'error', message: error.message });
  }

  // Clean up
  console.log('Clearing challenge from session');
  req.session.challenge = undefined;
});

/**
 * Handles the authentication initiation request
 * @param req - The request object
 * @param res - The response object
 */
app.get('/authenticate', async (req, res) => {
    console.log('Received authentication initiation request');
    console.log('Authenticators registered:', authenticators.size);

    // Check if there are any authenticators registered
    if (authenticators.size === 0) {
        console.error('No authenticators registered yet');
        res.status(400).json({ error: 'No authenticators registered yet' });
        return;
    }

    const userAuthenticators = Array.from(authenticators.values());
    const options: PublicKeyCredentialRequestOptionsJSON = await generateAuthenticationOptions({
      rpID: rpId,
      // Require users to use a previously-registered authenticator
      allowCredentials: userAuthenticators.map(authenticator => ({
        id: authenticator.credentialID,
        transports: authenticator.transports,
        type: 'public-key',
      })),
    });

    // Generate authentication options
    console.log('Authentication options:', options);

    // Store the challenge in the session
    req.session.challenge = options.challenge;
    res.json(options);
});

/**
 * Handles the authentication verification request
 * @param req - The request object
 * @param res - The response object
 */
app.post('/authenticate', async (req, res) => {
    const { body } = req;
    console.log('Received authentication verification request');
    console.dir(body, { depth: null });

    try {
        if (!req.session.challenge) {
          console.error('Challenge not found in session');
          throw new Error('Challenge not found in session');
        }

        const authenticator = authenticators.get(body.id);
        if (!authenticator) {
            console.error('Authenticator not found');
            throw new Error('Authenticator not found');
        }

        // Verify the authentication response
        const verificationParams = {
            response: body,
            expectedChallenge: req.session.challenge,
            expectedOrigin: origin,
            expectedRPID: rpId,
            requireUserVerification: true,
            credential: {
                id: authenticator.credentialID,
                publicKey: Buffer.from(authenticator.credentialPublicKey, 'base64url'),
                counter: authenticator.counter,
            },
        }
        console.log('Authentication verification parameters:');
        console.dir(verificationParams, { depth: null });
        const verificationResult = await verifyAuthenticationResponse(verificationParams);
        console.log('Authentication verification result:');
        console.dir(verificationResult, { depth: null });
        const { verified, authenticationInfo } = verificationResult;

        if (verified) {
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

          res.json(authenticator);
        }
    } catch (error: any) {
        console.error('Authentication error:', error);
        res.status(400).json({ status: 'error', message: error.message });
    }
});

/**
 * Handles the credentials request
 * @param req - The request object
 * @param res - The response object
 */
app.get('/credentials', (req, res) => {
    res.json(Array.from(authenticators.values()));
});

/**
 * Handles the credential deletion request
 * @param req - The request object
 * @param res - The response object
 */
app.delete('/credentials/:id', (req, res) => {
    const { id } = req.params;

    if (authenticators.has(id)) {
        authenticators.delete(id);
        res.json({ status: 'success' });
    } else {
        res.status(404).json({ status: 'error', message: 'Credential not found' });
    }
});

/**
 * Handles the configuration request
 * @param req - The request object
 * @param res - The response object
 */
app.get('/config', (req, res) => {
    res.json({
        environment: process.env.NODE_ENV || 'development',
        rpName,
        rpID: rpId,
        origin
    });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});