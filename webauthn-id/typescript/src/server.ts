import express from 'express';
import session from 'express-session';
import path from 'path';
import {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server';
import { parseFidoMetadataJWT } from './utils/fido-mds';
import { AuthenticatorModel, theUser, UserModel } from './types/models';
import { handleKeyRegistrationVerification, keyRegistrationRequest } from './utils/key-registration';
import { keyAuthenticationRequest, keyAuthenticationVerification } from './utils/key-authentication';

declare module 'express-session' {
  interface SessionData {
    challenge: string;
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const RP_ID = process.env.RP_ID || 'localhost';
const RP_NAME = process.env.RP_NAME || 'WebAuthn TypeScript Demo Default';
const ORIGIN = process.env.ORIGIN || `http://${RP_ID}:${PORT}`;

// In-memory storage - replace with database in production
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
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
  proxy: process.env.NODE_ENV === 'production', // Required for secure cookies in production
}));
// Add this right after session middleware to debug
app.use((req, res, next) => {
  console.log('Session ID:', req.sessionID);

  // Explicitly set CORS headers for every response
  res.header('Access-Control-Allow-Origin', req.headers.origin || ORIGIN);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type');

  next();
});

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

  const options = await keyRegistrationRequest(RP_NAME, RP_ID, theUser);
  req.session.challenge = options.challenge;

  // Force session save and wait for it
  await new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) reject(err);
      else resolve(true);
    });
  });

  console.log('Set-Cookie header:', res.getHeader('set-cookie'));
  console.log('Session saved successfully, sending options to client');
  res.json(options);
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

    const authenticator = await handleKeyRegistrationVerification(
      body,
      req.session.challenge,
      ORIGIN,
      RP_ID,
      theUser
    );

    authenticators.set(authenticator.credentialID, authenticator);
    console.log('Saved authenticator:', authenticator);

    res.json({ status: 'success', authenticator: authenticator });
  } catch (error: any) {
    console.error('Registration error:', error);
    console.error('Error stack:', error.stack);
    res.status(400).json({ status: 'error', message: error.message });
  }

  req.session.challenge = undefined;
});

/**
 * Handles the authentication initiation request
 * @param req - The request object
 * @param res - The response object
 * @returns The authentication options for the browser to pass to the authenticator
 */
app.get('/authenticate', async (req, res) => {
  console.log('Received authentication initiation request');

  try {
    const options = await keyAuthenticationRequest(RP_ID, authenticators);
    req.session.challenge = options.challenge;
    res.json(options);
  } catch (error: any) {
    console.error('Authentication error:', error);
    res.status(400).json({ error: error.message });
  }
});

/**
 * Handles the authentication verification request
 * @param req - The request object
 * @param res - The response object
 * @returns The verified authenticator object with all metadata
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

    const updatedAuthenticator = await keyAuthenticationVerification(
      body,
      req.session.challenge,
      ORIGIN,
      RP_ID,
      authenticator
    );

    res.json(updatedAuthenticator);
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
        rpID: RP_ID,
        rpName: RP_NAME,
        origin: ORIGIN,
    });
});

/**
 * Handles the FIDO metadata request with AAGUID as a query parameter
 * @param req - The request object
 * @param res - The response object
 */
app.get('/fido-metadata', (req: express.Request, res: express.Response) => {
  const aaguid = req.query.aaguid as string;

  if (!aaguid) {
    res.status(400).json({
      status: 'error',
      message: 'AAGUID query parameter is required'
    });
    return;
  }

  console.log(`Fetching FIDO metadata for AAGUID: ${aaguid}`);

  try {
    // Parse the metadata JWT if not already parsed
    const entries = parseFidoMetadataJWT();

    // Look up the specific AAGUID
    const metadata = entries.find(entry => entry.aaguid === aaguid);

    if (metadata) {
      res.json({
        status: 'success',
        metadata
      });
    } else {
      res.status(404).json({
        status: 'error',
        message: 'No metadata found for provided AAGUID'
      });
    }
  } catch (error: any) {
    console.error('Error fetching FIDO metadata:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch FIDO metadata',
      error: error.message
    });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});