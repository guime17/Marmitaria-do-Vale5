const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

const AUTH_SALT = 'MV_SEC_SALT_2026_V1';
const STORE_NAME = 'admin-auth';
const STORE_KEY = 'config';
const FALLBACK_EMAIL = 'marmitariadovale5@gmail.com';

function deriveCredentialHash(username, password) {
  const normUser = String(username || '').trim().toLowerCase();
  const payload = `${normUser}::${String(password || '')}`;
  return crypto
    .pbkdf2Sync(Buffer.from(payload, 'utf8'), Buffer.from(AUTH_SALT, 'utf8'), 100000, 32, 'sha256')
    .toString('hex');
}

function getFallbackAdminConfig() {
  if (!global.__MV_ADMIN_CONFIG__) {
    global.__MV_ADMIN_CONFIG__ = {
      username: 'admin',
      hash: deriveCredentialHash('admin', '12345678'),
      email: FALLBACK_EMAIL
    };
  }

  return global.__MV_ADMIN_CONFIG__;
}

async function getStoreOrNull() {
  try {
    return getStore({
      name: STORE_NAME,
      siteID: process.env.NETLIFY_SITE_ID,
      token: process.env.NETLIFY_API_TOKEN
    });
  } catch (_error) {
    return null;
  }
}

async function getAdminConfig() {
  const store = await getStoreOrNull();

  if (store) {
    try {
      const config = await store.getJSON(STORE_KEY);
      if (config && config.username && config.hash) {
        return config;
      }

      const defaultConfig = {
        username: 'admin',
        hash: deriveCredentialHash('admin', '12345678'),
        email: FALLBACK_EMAIL
      };

      await store.setJSON(STORE_KEY, defaultConfig);
      return defaultConfig;
    } catch (_error) {
      // Continua em modo de fallback local quando o ambiente do Netlify Blobs não foi configurado.
    }
  }

  return getFallbackAdminConfig();
}

async function persistAdminConfig(config) {
  const store = await getStoreOrNull();

  if (store) {
    try {
      await store.setJSON(STORE_KEY, config);
      return { persisted: true, fallback: false };
    } catch (_error) {
      // Fallback in-memory enquanto o ambiente do Netlify Blobs não estiver habilitado.
    }
  }

  global.__MV_ADMIN_CONFIG__ = { ...config };
  return { persisted: false, fallback: true };
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

    const persisted = await persistAdminConfig(updatedConfig);

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        success: true,
        username: newUsername,
        email: updatedConfig.email,
        hash: nextHash,
        fallback: persisted.fallback,
        message: persisted.fallback
          ? 'Senha atualizada em modo local porque o armazenamento persistente do Netlify Blobs não está configurado neste ambiente.'
          : 'Senha atualizada no armazenamento persistente do Netlify.'
      })
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        success: false,
        error: error && error.message
          ? error.message
          : 'Não foi possível atualizar a credencial persistente do painel.'
      })
    };
  }
};
