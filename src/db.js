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
  const { auth, ...rest } = store;
  return {
    ...rest,
    auth: { mode: auth.mode, header: auth.header || null, key_saved: !!auth.secret_enc },
  };
}

module.exports = { Db, publicView };
