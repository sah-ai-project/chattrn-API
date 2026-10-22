"use strict";
// A single JSON file holds the stores. Writes go to a temp file, then rename, so a crash
// never leaves a half-written file. Good enough for one process; swap for Postgres later.
const fs = require("node:fs");
const path = require("node:path");

class Db {
  constructor(file) {
    this.file = file;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    this.data = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : { stores: {} };
  }

  // Public view: never includes the encrypted key.
  list() {
    return Object.values(this.data.stores).map(publicView);
  }

  // Internal view (includes auth.secret_enc). Do not return this from an HTTP route.
  find(id) {
    return this.data.stores[id] || null;
  }

  put(store) {
    store.updated_at = new Date().toISOString();
    this.data.stores[store.id] = store;
    this.flush();
    return store;
  }

  flush() {
    const tmp = this.file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }
}

function publicView(store) {
  const { auth, chattrn, ...rest } = store;
  const out = { ...rest };
  if (auth) out.auth = { mode: auth.mode, header: auth.header || null, key_saved: !!auth.secret_enc };
  if (chattrn) out.chattrn = { base_url: chattrn.base_url, api_version: chattrn.api_version || null, capabilities: chattrn.capabilities || null, token_saved: !!chattrn.access_token_enc };
  return out;
}

module.exports = { Db, publicView };
