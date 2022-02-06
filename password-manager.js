'use strict';

// Password Manager
// =====================
// KVS has HMAC as its keys for each domain name instead of actual name
// use hmac(k,x) where k is sec key for HMAC to check if result exists
// MAX password is 64 bytes
// use PKBDF2 to generate keys (derive) from master key
// from .init() potentially
// call PKCS2 once
// use AES-GCM for passwords

/********* External Imports ********/

const {
  byteArrayToString,
  genRandomSalt,
  untypedToTypedArray,
  stringToByteArray,
  bufferToUntypedArray,
} = require('./lib');
const { subtle } = require('crypto').webcrypto;

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   *  You may design the constructor with any parameters you would like.
   * Return Type: void
   */
  constructor() {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      kvs: {},
      masterKeySalt: null,
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      masterKey: null,
      domainHMACKey: null,
      passwordHMACKey: null,
    };

    this.data.version = 'CS 255 Password Manager v1.0';
    // Flag to indicate whether password manager is "ready" or not
    this.ready = true;
  }

  /**
   * Creates an empty keychain with the given password. Once the constructor
   * has finished, the password manager should be in a ready state.
   *
   * Arguments:
   *   password: string
   * Return Type: void
   */
  static async init(password) {
    const keychain = new Keychain();
    keychain.ready = false;
    keychain.data.masterKeySalt = Buffer.from(genRandomSalt(128));

    const seed = await subtle.importKey(
      'raw',
      stringToByteArray(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    keychain.secrets.masterKey = await subtle.deriveKey(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: keychain.data.masterKeySalt,
        iterations: this.PBKDF2_ITERATIONS,
      },
      seed,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign']
    );

    // Arbitrary strings
    // const hmacKeySeed = genRandomSalt(128);
    const hmacKeySeed = 'HMAC_KEY_SEED';
    // const aesKeySeed = genRandomSalt(128);
    const aesKeySeed = 'AES_KEY_SEED';

    const domainHMACSig = await subtle.sign(
      'HMAC',
      keychain.secrets.masterKey,
      stringToByteArray(hmacKeySeed)
    );

    keychain.secrets.domainHMACKey = await subtle.importKey(
      'raw',
      domainHMACSig,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );

    const passwordHMACSig = await subtle.sign(
      'HMAC',
      keychain.secrets.masterKey,
      stringToByteArray(aesKeySeed)
    );
    keychain.secrets.passwordHMACKey = await subtle.importKey(
      'raw',
      passwordHMACSig,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );

    keychain.ready = true;
    return keychain;
  }

  /**
   * Loads the keychain state from the provided representation (repr). The
   * repr variable will contain a JSON encoded serialization of the contents
   * of the KVS (as returned by the dump function). The trustedDataCheck
   * is an *optional* SHA-256 checksum that can be used to validate the
   * integrity of the contents of the KVS. If the checksum is provided and the
   * integrity check fails, an exception should be thrown. You can assume that
   * the representation passed to load is well-formed (i.e., it will be
   * a valid JSON object).Returns a Keychain object that contains the data
   * from repr.
   *
   * Arguments:
   *   password:           string
   *   repr:               string
   *   trustedDataCheck: string
   * Return Type: Keychain
   */
  static async load(password, repr, trustedDataCheck) {
    if (
      JSON.stringify(trustedDataCheck) !==
      JSON.stringify(await subtle.digest('SHA-256', stringToByteArray(repr)))
    ) {
      throw 'Integrity check failed.';
    }
    const keychain = new Keychain();
    keychain.ready = false;
    keychain.data = JSON.parse(repr);
    const seed = await subtle.importKey(
      'raw',
      stringToByteArray(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    keychain.secrets.masterKey = await subtle.deriveKey(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: Buffer.from(keychain.data.masterKeySalt),
        iterations: this.PBKDF2_ITERATIONS,
      },
      seed,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign']
    );
    const hmacKeySeed = 'HMAC_KEY_SEED';
    const aesKeySeed = 'AES_KEY_SEED';

    const domainHMACSig = await subtle.sign(
      'HMAC',
      keychain.secrets.masterKey,
      stringToByteArray(hmacKeySeed)
    );
    keychain.secrets.domainHMACKey = await subtle.importKey(
      'raw',
      domainHMACSig,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );

    const passwordHMACSig = await subtle.sign(
      'HMAC',
      keychain.secrets.masterKey,
      stringToByteArray(aesKeySeed)
    );
    keychain.secrets.passwordHMACKey = await subtle.importKey(
      'raw',
      passwordHMACSig,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );

    keychain.ready = true;
    return keychain;
  }

  /**
   * Returns a JSON serialization of the contents of the keychain that can be
   * loaded back using the load function. The return value should consist of
   * an array of two strings:
   *   arr[0] = JSON encoding of password manager
   *   arr[1] = SHA-256 checksum (as a string)
   * As discussed in the handout, the first element of the array should contain
   * all of the data in the password manager. The second element is a SHA-256
   * checksum computed over the password manager to preserve integrity. If the
   * password manager is not in a ready-state, return null.
   *
   * Return Type: array
   */
  async dump() {
    if (!this.ready) throw 'Error: keychain uninitialized.';
    const repr = JSON.stringify(this.data);
    const hash = await subtle.digest('SHA-256', stringToByteArray(repr));
    return [repr, hash];
  }

  /**
   * Fetches the data (as a string) corresponding to the given domain from the KVS.
   * If there is no entry in the KVS that matches the given domain, then return
   * null. If the password manager is not in a ready state, throw an exception. If
   * tampering has been detected with the records, throw an exception.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<string>
   */
  async get(name) {
    // Check in ready state
    // Get domain HMAC
    // Get value for key
    // Decrypt from AES-GCM
    // Find domain as substring and compare to domain HMAC
    // Return decrypted password or throw exception
    if (!this.ready) throw 'Error: keychain uninitialized.';

    // Convert domain name to KVS lookup key
    const domain = bufferToUntypedArray(
      await subtle.sign(
        {
          name: 'HMAC',
          hash: 'SHA-256',
        },
        this.secrets.domainHMACKey,
        stringToByteArray(name)
      )
    );
    // Get corresponding value for domain
    let val = this.data.kvs[domain];
    if (val == undefined) return null;
    const iv = untypedToTypedArray(val.iv);
    // Decrypt value from KVS
    const to_decrypt = val.password;
    let decrypted = await subtle.decrypt(
      { name: 'AES-GCM', iv: iv, additionalData: untypedToTypedArray(domain) },
      this.secrets.passwordHMACKey,
      untypedToTypedArray(to_decrypt)
    );

    return new Promise((resolve, _) => {
      resolve(byteArrayToString(decrypted));
    });
  }

  /**
   * Inserts the domain and associated data into the KVS. If the domain is
   * already in the password manager, this method should update its value. If
   * not, create a new entry in the password manager. If the password manager is
   * not in a ready state, throw an exception.
   *
   * Arguments:
   *   name: string
   *   value: string
   * Return Type: void
   */
  async set(name, value) {
    const domain = bufferToUntypedArray(
      await subtle.sign(
        {
          name: 'HMAC',
          hash: 'SHA-256',
        },
        this.secrets.domainHMACKey,
        stringToByteArray(name)
      )
    );

    const iv = genRandomSalt(16); // determine size, 96 is per mdn rec but we use 16
    const padded =
      // "to do"
      value;
    const password = await subtle.encrypt(
      { name: 'AES-GCM', iv: stringToByteArray(iv), additionalData: untypedToTypedArray(domain) },
      this.secrets.passwordHMACKey,
      stringToByteArray(padded)
    );
    this.data.kvs[domain] = {
      password: bufferToUntypedArray(password),
      iv: bufferToUntypedArray(stringToByteArray(iv)),
    };
  }

  /**
   * Removes the record with name from the password manager. Returns true
   * if the record with the specified name is removed, false otherwise. If
   * the password manager is not in a ready state, throws an exception.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<boolean>
   */
  async remove(name) {
    if (!this.ready) throw 'Error: keychain uninitialized.';
    // Convert domain name to KVS lookup key
    const domain = bufferToUntypedArray(
      await subtle.sign(
        {
          name: 'HMAC',
          hash: 'SHA-256',
        },
        this.secrets.domainHMACKey,
        stringToByteArray(name)
      )
    );
    // Get corresponding value for domain
    let val = this.data.kvs[domain];
    if (val == undefined) return false;
    delete this.data.kvs[domain];
    return true;
  }

  static get PBKDF2_ITERATIONS() {
    return 100000;
  }
}

module.exports = {
  Keychain: Keychain,
};
