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
      body: JSON.stringify({ success: false, error: 'Method not allowed' })
    };
  }

  try {
    const body = JSON.parse(event.body || '{}');
    const username = String(body.username || '').trim().toLowerCase();
    const password = String(body.password || '');
    const newUsername = String(body.newUsername || '').trim().toLowerCase();
    const newPassword = String(body.newPassword || '');
    const email = String(body.email || '').trim();

    if (!username || !password) {
      return {
        statusCode: 401,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ success: false, error: 'Credenciais atuais ausentes.' })
      };
    }

    if (!newUsername || newUsername.length < 3) {
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ success: false, error: 'O usuário deve ter pelo menos 3 caracteres.' })
      };
    }

    if (newPassword.length < 6) {
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ success: false, error: 'A nova senha deve ter pelo menos 6 caracteres.' })
      };
    }

    const config = await getAdminConfig();
    const currentUser = String(config.username || 'admin').trim().toLowerCase();
    const currentHash = String(config.hash || '').trim();

    const valid =
      username === currentUser &&
      deriveCredentialHash(username, password) === currentHash;

    if (!valid) {
      return {
        statusCode: 401,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ success: false, error: 'Senha atual incorreta.' })
      };
    }

    const nextHash = deriveCredentialHash(newUsername, newPassword);
    const updatedConfig = {
      username: newUsername,
      hash: nextHash,
      email: email || config.email || 'marmitariadovale5@gmail.com'
    };

    const store = getStore({ name: STORE_NAME });
    await store.setJSON(STORE_KEY, updatedConfig);

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        success: true,
        username: newUsername,
        email: updatedConfig.email,
        hash: nextHash,
        message: 'Senha atualizada no armazenamento persistente do Netlify.'
      })
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        success: false,
        error: 'Não foi possível atualizar a credencial persistente do painel.'
      })
    };
  }
};
