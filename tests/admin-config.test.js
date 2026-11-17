const test = require('node:test');
const assert = require('node:assert/strict');

const updateAdminHandler = require('../netlify/functions/update-admin.js');

test('update-admin endpoint succeeds even when Netlify Blobs env is not configured', async () => {
  const event = {
    httpMethod: 'POST',
    body: JSON.stringify({
      username: 'admin',
      password: '12345678',
      newUsername: 'admin',
      newPassword: '87654321',
      email: 'marmitariadovale5@gmail.com'
    })
  };

  const response = await updateAdminHandler.handler(event);
  const payload = JSON.parse(response.body);

  assert.equal(response.statusCode, 200);
  assert.equal(payload.success, true);
});
