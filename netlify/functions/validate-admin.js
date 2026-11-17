const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

const AUTH_SALT = 'MV_SEC_SALT_2026_V1';
const STORE_NAME = 'admin-auth';
const STORE_KEY = 'config';

function deriveCredentialHash(username, password) {
  const normUser = String(username || '').trim().toLowerCase();
  const payload = `${normUser}::${String(password || '')}`;
  return crypto
    .pbkdf2Sync(Buffer.from(payload, 'utf8'), Buffer.from(AUTH_SALT, 'utf8'), 100000, 32, 'sha256')
    .toString('hex');
}

async function getAdminConfig() {
  const store = getStore({ name: STORE_NAME });
  const config = await store.getJSON(STORE_KEY);

  if (config && config.username && config.hash) {
    return config;
  }

  const defaultConfig = {
    username: 'admin',
    hash: deriveCredentialHash('admin', '12345678'),
    email: 'marmitariadovale5@gmail.com'
  };

  await store.setJSON(STORE_KEY, defaultConfig);
  return defaultConfig;
}

exports.handler = async function handler(event) {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ valid: false, error: 'Method not allowed' })
    };
  }

  try {
    const body = JSON.parse(event.body || '{}');
    const username = String(body.username || '').trim().toLowerCase();
    const password = String(body.password || '');

    if (!username || !password) {
      return {
        statusCode: 401,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ valid: false, error: 'Missing credentials' })
      };
    }

    const config = await getAdminConfig();
    const candidateHash = deriveCredentialHash(username, password);
    const userMatches = username === String(config.username || '').trim().toLowerCase();
    const hashMatches = candidateHash === String(config.hash || '');

    return {
      statusCode: userMatches && hashMatches ? 200 : 401,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ valid: Boolean(userMatches && hashMatches) })
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ valid: false, error: 'Server-side validation failed' })
    };
  }
};
