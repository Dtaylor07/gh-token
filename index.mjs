import express from 'express';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { Pool } from 'pg';
import cron from 'node-cron';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Allowed IP
const ALLOWED_IP = process.env.ALLOWED_IP;
if (!ALLOWED_IP) {
  console.error('❌ Missing ALLOWED_IP in environment variables');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(cookieParser());
app.use(express.static('public'));
app.use(express.json());
app.set('trust proxy', true);

// IP Restriction Middleware
app.use((req, res, next) => {
  const xForwardedFor = req.headers['x-forwarded-for'];
  const ip = xForwardedFor ? xForwardedFor.split(',')[0].trim() : req.ip;

  console.log('Client IP:', ip); // Debug log

  if (ip === ALLOWED_IP || ip === `::ffff:${ALLOWED_IP}`) {
    next();
  } else {
    res.status(403).send('Access forbidden - Twingate is not enabled');
  }
});

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const PRIVATE_KEY = process.env.GITHUB_PRIVATE_KEY;
const ORG_NAME = 'AquaNow'; // The organization name to validate membership

if (!PRIVATE_KEY) {
  console.error('❌ Missing PRIVATE_KEY');
  process.exit(1);
}

// Start GitHub OAuth
app.get('/', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const signedState = jwt.sign({ state }, PRIVATE_KEY, { algorithm: 'RS256' });
  res.cookie('oauth_state', signedState, { httpOnly: true });

  const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=user&user:email&login&&state=${state}`;
  res.redirect(githubAuthUrl);
});

// OAuth Callback
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const signedState = req.cookies.oauth_state;

  if (!signedState || !state) {
    return res.status(403).send('Invalid state');
  }

  try {
    const decoded = jwt.verify(signedState, PRIVATE_KEY, { algorithms: ['RS256'] });
    if (state !== decoded.state) {
      return res.status(403).send('State mismatch');
    }

    res.clearCookie('oauth_state');

    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: REDIRECT_URI,
      }),
    });

    const tokenData = await tokenRes.json();
    if (tokenData.error) return res.status(400).json({ error: tokenData.error });

    // Get user info from GitHub
    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `token ${tokenData.access_token}`,
        Accept: 'application/vnd.github+json',
      },
    });
    const userData = await userRes.json();
    if (!userData.login) return res.status(400).send('GitHub user fetch failed');

    // Fetch user's primary email (since it may not be public)
    let userEmail = userData.email;
    if (!userEmail) {
      const emailRes = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `token ${tokenData.access_token}`,
          Accept: 'application/vnd.github+json',
        },
      });
      const emails = await emailRes.json();
      const primaryEmail = emails.find(e => e.primary && e.verified);
      userEmail = primaryEmail?.email || emails[0]?.email || null;
    }

    // Validate organization membership
    const membershipRes = await fetch(`https://api.github.com/orgs/${ORG_NAME}/memberships/${userData.login}`, {
      headers: {
        Authorization: `token ${tokenData.access_token}`,
        Accept: 'application/vnd.github+json',
      },
    });

    if (membershipRes.status !== 200) {
      return res.status(403).send('User is not a member of the required organization');
    }

    const membershipData = await membershipRes.json();
    if (membershipData.state !== 'active') {
      return res.status(403).send('User is not an active member of the required organization');
    }

    // Token expiration time is 2 hours
    const expiresAt = new Date(Date.now() + 7200 * 1000).toISOString(); // 2 hours

    // Insert token and email into database
    await pool.query(
      `INSERT INTO tokens (state, access_token, user_email, authentication_status, method, status, ip_address, expires_at, token_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [state, tokenData.access_token, userEmail, 'pass', 'GUI', 'active', req.ip, expiresAt, 'Enabled']
    );

    // Render response
    const html = fs.readFileSync(path.resolve('templates/page.html'), 'utf8');
    res.send(html.replace('${ACCESS_TOKEN}', tokenData.access_token));
  } catch (err) {
    console.error(err);
    res.status(500).send('OAuth Error');
  }
});

// Retrieve token by state
app.get('/token/:state', async (req, res) => {
  const { state } = req.params;

  const result = await pool.query(`SELECT access_token, expires_at, token_status FROM tokens WHERE state = $1`, [state]);
  if (result.rowCount === 0) return res.status(404).send('Token not found');

  const { access_token, expires_at, token_status } = result.rows[0];
  if (token_status === 'Disabled' || Date.now() > new Date(expires_at).getTime()) {
    await pool.query(`DELETE FROM tokens WHERE state = $1`, [state]);
    return res.status(401).send('Token expired or disabled');
  }

  res.json({ access_token });
});

// Cron job to revoke expired or disabled tokens
cron.schedule('* * * * *', async () => {
  try {
    const result = await pool.query(
      `SELECT state, access_token FROM tokens WHERE token_status = 'Disabled' OR expires_at < NOW()`
    );

    for (const row of result.rows) {
      const { state, access_token } = row;

      // Revoke token on GitHub
      const revokeRes = await fetch(`https://api.github.com/applications/${CLIENT_ID}/token`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
          'Accept': 'application/vnd.github.v3+json',
        },
        body: JSON.stringify({ access_token }),
      });

      if (revokeRes.status === 204) {
        console.log(`✅ Token revoked successfully: ${access_token}`);
      } else {
        const errText = await revokeRes.text();
        console.warn(`⚠️ GitHub token revocation failed: ${access_token}`, errText);
      }

      // Delete token from database
      await pool.query(`DELETE FROM tokens WHERE state = $1`, [state]);
      console.log(`🗑️ Token deleted from database: ${access_token}`);
    }
  } catch (err) {
    console.error('❌ Cron job error:', err);
  }
});

// List all "Enabled" tokens
app.get('/admin/enabled-tokens', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT state, access_token, user_email, expires_at FROM tokens WHERE token_status = 'Enabled'`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('❌ Error fetching enabled tokens:', err);
    res.status(500).send('Failed to fetch enabled tokens');
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
});
