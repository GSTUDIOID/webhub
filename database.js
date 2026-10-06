require('dotenv').config();
const https = require("https");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

if (!SUPABASE_URL) {
  throw new Error("SUPABASE_URL belum diset.");
}

if (!SUPABASE_SECRET_KEY) {
  throw new Error("SUPABASE_SECRET_KEY belum diset.");
}

function supabaseRequest(path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, SUPABASE_URL);

    const requestOptions = {
      method: options.method || "GET",
      hostname: url.hostname,
      path: url.pathname + url.search,
      headers: {
        "Content-Type": "application/json",
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": `Bearer ${SUPABASE_SECRET_KEY}`,
        ...(options.headers || {})
      }
    };

    const req = https.request(requestOptions, (res) => {
      let body = "";

      res.on("data", (chunk) => {
        body += chunk;
      });

      res.on("end", () => {
        let data;

        try {
          data = body ? JSON.parse(body) : null;
        } catch {
          data = body;
        }

        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(data);
        } else {
          const error = new Error(
            data?.message ||
            data?.error_description ||
            `Supabase request gagal (${res.statusCode})`
          );

          error.status = res.statusCode;
          error.details = data;

          reject(error);
        }
      });
    });

    req.on("error", reject);

    if (options.body) {
      req.write(JSON.stringify(options.body));
    }

    req.end();
  });
}

async function select(table, query = "") {
  return supabaseRequest(`/rest/v1/${table}${query}`);
}

async function insert(table, data) {
  return supabaseRequest(`/rest/v1/${table}`, {
    method: "POST",
    headers: {
      "Prefer": "return=representation"
    },
    body: data
  });
}

async function update(table, query, data) {
  return supabaseRequest(`/rest/v1/${table}${query}`, {
    method: "PATCH",
    headers: {
      "Prefer": "return=representation"
    },
    body: data
  });
}

async function remove(table, query) {
  return supabaseRequest(`/rest/v1/${table}${query}`, {
    method: "DELETE",
    headers: {
      "Prefer": "return=representation"
    }
  });
}

module.exports = {
  supabaseRequest,
  select,
  insert,
  update,
  remove
};

