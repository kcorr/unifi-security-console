// Forgot the dashboard password? This removes the sign-in account and ends every session, so the next visit to the
// dashboard shows the set-up page again. Environments, API keys, history and settings are kept.
//
//   docker exec unifi-security-console node --disable-warning=ExperimentalWarning server/reset-login.ts

import { DATA_DIR } from './config.ts';
import { openDb } from './db.ts';
import { Auth } from './auth.ts';

const db = openDb(DATA_DIR, 'app.db');
const auth = new Auth(db);
const name = auth.username;
if (name === null) console.log('There is no sign-in account yet. Open the dashboard to create one.');
else {
  auth.reset();
  console.log(`Removed the sign-in account "${name}" and ended every session. Open the dashboard to create a new account.`);
}
db.close();
