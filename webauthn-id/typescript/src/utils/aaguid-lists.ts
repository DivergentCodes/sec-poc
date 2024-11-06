
import fs from 'fs';
import path from 'path';
import { RecognizedAAGUID } from '../types/types';

let passkeyEntries: RecognizedAAGUID[] = [];

/**
 * Parses the passkeydeveloper_passkey-authenticator-aaguids.json file containing AAGUID mappings
 * @returns Array of passkey entries
 */
function parsePasskeyDeveloperFile(): RecognizedAAGUID[] {
  try {
    const filePath = path.join(__dirname, '../../data/passkeydeveloper_passkey-authenticator-aaguids.json');
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(fileContent);

    // Convert object to array of RecognizedAAGUID objects
    return Object.entries(parsed).map(([aaguid, details]: [string, any]) => ({
      aaguid,
      name: details.name,
      icon_light: details.icon_light,
      icon_dark: details.icon_dark
    }));
  } catch (error) {
    console.error('Error parsing passkeydeveloper_passkey-authenticator-aaguids.json:', error);
    return [];
  }
}[]

/**
 * Look up an authenticator entry by its AAGUID from the passkeydeveloper list
 * @param aaguid - The AAGUID to search for
 * @returns The matching authenticator entry or undefined if not found
 */
function getPasskeyEntryByAAGUID(aaguid: string): RecognizedAAGUID | undefined {
  if (passkeyEntries.length === 0) {
    passkeyEntries = parsePasskeyDeveloperFile();
  }
  return passkeyEntries.find(entry => entry.aaguid.toLowerCase() === aaguid.toLowerCase());
}

/**
 * Look up an authenticator entry by its AAGUID from community maintained lists.
 * @param aaguid - The AAGUID to search for
 * @returns The matching authenticator entry or undefined if not found
 */
export function lookupRecognizedAAGUID(aaguid: string): RecognizedAAGUID | undefined {
  return getPasskeyEntryByAAGUID(aaguid);
}
