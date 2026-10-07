require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const https = require("https");

const {
  select,
  insert,
  update,
  remove
} = require("./database");

const app = express();

const PORT = process.env.PORT || 3000;
const SESSION_DAYS = 7;
const COOKIE_NAME = "webhub_session";
function getStorageObject(path) {
  return new Promise((resolve, reject) => {
    const supabaseUrl = process.env.SUPABASE_URL;
    const secretKey = process.env.SUPABASE_SECRET_KEY;

    if (!supabaseUrl || !secretKey) {
      return reject(new Error("Konfigurasi Supabase belum lengkap."));
    }

    const url = new URL(`/storage/v1/object/public/${path}`, supabaseUrl);

    const request = https.request(
      {
        method: "GET",
        hostname: url.hostname,
        path: url.pathname,
        headers: {
          apikey: secretKey,
          Authorization: `Bearer ${secretKey}`
        }
      },
      (response) => {
        const chunks = [];

        response.on("data", chunk => chunks.push(chunk));

        response.on("end", () => {
          resolve({
            statusCode: response.statusCode,
            contentType: response.headers["content-type"] || "application/octet-stream",
            body: Buffer.concat(chunks)
          });
        });
      }
    );

    request.on("error", reject);
    request.end();
  });
}

async function uploadStorageObject(path, buffer, contentType) {
  return new Promise((resolve, reject) => {
    const supabaseUrl = process.env.SUPABASE_URL;
    const secretKey = process.env.SUPABASE_SECRET_KEY;

    if (!supabaseUrl || !secretKey) {
      return reject(new Error("Konfigurasi Supabase belum lengkap."));
    }

    const url = new URL(`/storage/v1/object/${path}`, supabaseUrl);

    const request = https.request(
      {
        method: "POST",
        hostname: url.hostname,
        path: url.pathname,
        headers: {
          apikey: secretKey,
          Authorization: `Bearer ${secretKey}`,
          "Content-Type": contentType || "application/octet-stream",
          "Content-Length": buffer.length,
          "x-upsert": "true"
        }
      },
      (response) => {
        const chunks = [];

        response.on("data", chunk => chunks.push(chunk));

        response.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");

          resolve({
            statusCode: response.statusCode,
            body
          });
        });
      }
    );

    request.on("error", reject);
    request.write(buffer);
    request.end();
  });
}

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index1000.html");
});

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function validUsername(username) {
  return /^[a-z0-9_-]{3,30}$/.test(username);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function createSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashSessionToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function sessionExpiry() {
  const date = new Date();
  date.setDate(date.getDate() + SESSION_DAYS);
  return date.toISOString();
}

function setSessionCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
    path: "/"
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/"
  });
}

async function getCurrentUser(req) {
  const token = req.cookies[COOKIE_NAME];

  if (!token) {
    return null;
  }

  const tokenHash = hashSessionToken(token);

  const sessions = await select(
    "sessions",
    `?select=id,user_id,expires_at&token_hash=eq.${encodeURIComponent(tokenHash)}&expires_at=gt.${encodeURIComponent(new Date().toISOString())}&limit=1`
  );

  if (!Array.isArray(sessions) || sessions.length === 0) {
    return null;
  }

  const users = await select(
    "users",
    `?select=id,username,email,created_at,updated_at&id=eq.${encodeURIComponent(sessions[0].user_id)}&limit=1`
  );

  if (!Array.isArray(users) || users.length === 0) {
    return null;
  }

  return users[0];
}

async function requireAuth(req, res, next) {
  try {
    const user = await getCurrentUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Sesi tidak ditemukan atau sudah berakhir."
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("AUTH ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal memeriksa sesi."
    });
  }
}

app.post(
  "/api/projects/:projectId/assets",
  requireAuth,
  express.raw({
    type: "*/*",
    limit: "10mb"
  }),
  async (req, res) => {
    try {
      const project = await getOwnedProject(
        req.params.projectId,
        req.user.id
      );

      if (!project) {
        return res.status(404).json({
          success: false,
          message: "Project tidak ditemukan."
        });
      }

      const filename = String(req.query.filename || "").trim();
      const contentType = String(
        req.headers["content-type"] || "application/octet-stream"
      ).split(";")[0].trim();

      if (!filename) {
        return res.status(400).json({
          success: false,
          message: "Nama file wajib diisi melalui query filename."
        });
      }

      if (
        filename.length > 255 ||
        filename.includes("/") ||
        filename.includes("\\") ||
        filename.includes("..")
      ) {
        return res.status(400).json({
          success: false,
          message: "Nama file tidak valid."
        });
      }

      const allowedTypes = new Set([
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/svg+xml",
        "image/x-icon"
      ]);

      if (!allowedTypes.has(contentType)) {
        return res.status(415).json({
          success: false,
          message: "Tipe asset tidak didukung."
        });
      }

      if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
        return res.status(400).json({
          success: false,
          message: "Data asset kosong."
        });
      }

      const storagePath = `webhub-assets/${project.id}/${filename}`;

      const uploaded = await uploadStorageObject(
        storagePath,
        req.body,
        contentType
      );

      if (uploaded.statusCode < 200 || uploaded.statusCode >= 300) {
        console.error("STORAGE UPLOAD ERROR:", uploaded.statusCode, uploaded.body);

        return res.status(500).json({
          success: false,
          message: "Gagal mengupload asset."
        });
      }

      return res.status(201).json({
        success: true,
        message: "Asset berhasil diupload.",
        asset: {
          filename,
          mime_type: contentType,
          size_bytes: req.body.length,
          project_id: project.id,
          url: `/project/${project.slug}/${filename}`
        }
      });
    } catch (error) {
      console.error("ASSET UPLOAD ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Gagal mengupload asset."
      });
    }
  }
);

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "WEBHUB",
    status: "online"
  });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const confirmPassword = String(req.body.confirmPassword || "");

    if (!validUsername(username)) {
      return res.status(400).json({
        success: false,
        message: "Username harus 3-30 karakter dan hanya boleh berisi huruf, angka, underscore, atau tanda minus."
      });
    }

    if (!validEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Format email tidak valid."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password minimal 8 karakter."
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Konfirmasi password tidak cocok."
      });
    }

    const existing = await select(
      "users",
      `?select=id,username,email&or=(username.eq.${encodeURIComponent(username)},email.eq.${encodeURIComponent(email)})&limit=2`
    );

    if (Array.isArray(existing) && existing.length > 0) {
      const usernameExists = existing.some(
        user => user.username === username
      );

      const emailExists = existing.some(
        user => user.email === email
      );

      if (usernameExists) {
        return res.status(409).json({
          success: false,
          message: "Username sudah digunakan."
        });
      }

      if (emailExists) {
        return res.status(409).json({
          success: false,
          message: "Email sudah digunakan."
        });
      }
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const created = await insert("users", {
      username,
      email,
      password_hash: passwordHash
    });

    if (!Array.isArray(created) || created.length === 0) {
      throw new Error("Gagal membuat user.");
    }

    const user = created[0];

    const token = createSessionToken();

    await insert("sessions", {
      user_id: user.id,
      token_hash: hashSessionToken(token),
      expires_at: sessionExpiry()
    });

    setSessionCookie(res, token);

    return res.status(201).json({
      success: true,
      message: "Akun WEBHUB berhasil dibuat.",
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal membuat akun."
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const identifier = String(
      req.body.identifier ||
      req.body.username ||
      req.body.email ||
      ""
    ).trim().toLowerCase();

    const password = String(req.body.password || "");

    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        message: "Username/email dan password wajib diisi."
      });
    }

    const users = await select(
      "users",
      `?select=id,username,email,password_hash,created_at,updated_at&or=(username.eq.${encodeURIComponent(identifier)},email.eq.${encodeURIComponent(identifier)})&limit=1`
    );

    if (!Array.isArray(users) || users.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Username/email atau password salah."
      });
    }

    const user = users[0];

    const passwordValid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordValid) {
      return res.status(401).json({
        success: false,
        message: "Username/email atau password salah."
      });
    }

    const token = createSessionToken();

    await insert("sessions", {
      user_id: user.id,
      token_hash: hashSessionToken(token),
      expires_at: sessionExpiry()
    });

    setSessionCookie(res, token);

    return res.json({
      success: true,
      message: "Login berhasil.",
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal melakukan login."
    });
  }
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

app.post("/api/auth/logout", async (req, res) => {
  try {
    const token = req.cookies[COOKIE_NAME];

    if (token) {
      const tokenHash = hashSessionToken(token);

      await remove(
        "sessions",
        `?token_hash=eq.${encodeURIComponent(tokenHash)}`
      );
    }

    clearSessionCookie(res);

    return res.json({
      success: true,
      message: "Logout berhasil."
    });
  } catch (error) {
    console.error("LOGOUT ERROR:", error);

    clearSessionCookie(res);

    return res.status(500).json({
      success: false,
      message: "Logout selesai, tetapi terjadi kesalahan saat membersihkan sesi."
    });
  }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  return res.json({
    success: true,
    message: "Jika email terdaftar, instruksi pemulihan akun akan diproses."
  });
});

function createProjectSlug(name) {
  const base = String(name || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 90);

  return base || "project";
}

app.get("/api/projects", requireAuth, async (req, res) => {
  try {
    const projects = await select(
      "projects",
      `?select=id,name,slug,description,visibility,created_at,updated_at&user_id=eq.${encodeURIComponent(req.user.id)}&order=updated_at.desc`
    );

    return res.json({
      success: true,
      projects: Array.isArray(projects) ? projects : []
    });
  } catch (error) {
    console.error("PROJECT LIST ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal mengambil daftar project."
    });
  }
});

app.post("/api/projects", requireAuth, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const description = String(req.body.description || "").trim();
    const visibility = String(req.body.visibility || "private").trim().toLowerCase();

    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Nama project wajib diisi."
      });
    }

    if (name.length > 100) {
      return res.status(400).json({
        success: false,
        message: "Nama project maksimal 100 karakter."
      });
    }

    if (!["private", "public"].includes(visibility)) {
      return res.status(400).json({
        success: false,
        message: "Visibility project tidak valid."
      });
    }

    const baseSlug = createProjectSlug(name);
    let slug = baseSlug;

    for (let attempt = 1; attempt <= 20; attempt++) {
      const existing = await select(
        "projects",
        `?select=id&slug=eq.${encodeURIComponent(slug)}&limit=1`
      );

      if (!Array.isArray(existing) || existing.length === 0) {
        break;
      }

      slug = `${baseSlug}-${attempt + 1}`;
    }

    const created = await insert("projects", {
      user_id: req.user.id,
      name,
      slug,
      description,
      visibility
    });

    if (!Array.isArray(created) || created.length === 0) {
      throw new Error("Project tidak berhasil dibuat.");
    }

    return res.status(201).json({
      success: true,
      message: "Project berhasil dibuat.",
      project: created[0]
    });
  } catch (error) {
    console.error("PROJECT CREATE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal membuat project."
    });
  }
});
async function getOwnedProject(projectId, userId) {
  const projects = await select(
    "projects",
    `?select=id,name,slug,user_id&and=(id.eq.${encodeURIComponent(projectId)},user_id.eq.${encodeURIComponent(userId)})&limit=1`
  );

  if (!Array.isArray(projects) || projects.length === 0) {
    return null;
  }

  return projects[0];
}

app.get("/api/projects/:projectId", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const projects = await select(
      "projects",
      `?select=id,user_id,name,slug,description,visibility,created_at,updated_at&id=eq.${encodeURIComponent(project.id)}&user_id=eq.${encodeURIComponent(req.user.id)}&limit=1`
    );

    if (!Array.isArray(projects) || projects.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const files = await select(
      "project_files",
      `?select=id,filename,mime_type,size_bytes,created_at,updated_at&project_id=eq.${encodeURIComponent(project.id)}&order=filename.asc`
    );

    const versions = await select(
      "project_versions",
      `?select=id,version_number,name,description,created_at&project_id=eq.${encodeURIComponent(project.id)}&order=version_number.desc`
    );

    return res.json({
      success: true,
      project: projects[0],
      stats: {
        files: Array.isArray(files) ? files.length : 0,
        versions: Array.isArray(versions) ? versions.length : 0
      }
    });
  } catch (error) {
    console.error("PROJECT DETAIL ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal mengambil detail project."
    });
  }
});
app.get("/api/projects/:projectId/files", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const files = await select(
      "project_files",
      `?select=id,filename,mime_type,size_bytes,created_at,updated_at&project_id=eq.${encodeURIComponent(project.id)}&order=filename.asc`
    );

    return res.json({
      success: true,
      project: {
        id: project.id,
        name: project.name,
        slug: project.slug
      },
      files: Array.isArray(files) ? files : []
    });
  } catch (error) {
    console.error("FILE LIST ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal mengambil daftar file."
    });
  }
});

app.post("/api/projects/:projectId/files", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const filename = String(req.body.filename || "").trim();
    const content = String(req.body.content || "");
    const mimeType = String(
      req.body.mime_type || req.body.mimeType || "text/plain"
    ).trim();

    if (!filename) {
      return res.status(400).json({
        success: false,
        message: "Nama file wajib diisi."
      });
    }

    if (filename.length > 255) {
      return res.status(400).json({
        success: false,
        message: "Nama file maksimal 255 karakter."
      });
    }

    if (filename.includes("/") || filename.includes("\\") || filename.includes("..")) {
      return res.status(400).json({
        success: false,
        message: "Nama file tidak valid."
      });
    }

    const sizeBytes = Buffer.byteLength(content, "utf8");

    if (sizeBytes > 1024 * 1024) {
      return res.status(413).json({
        success: false,
        message: "Ukuran file maksimal 1 MB."
      });
    }

    const existing = await select(
      "project_files",
      `?select=id&project_id=eq.${encodeURIComponent(project.id)}&filename=eq.${encodeURIComponent(filename)}&limit=1`
    );

    if (Array.isArray(existing) && existing.length > 0) {
      return res.status(409).json({
        success: false,
        message: "File dengan nama tersebut sudah ada."
      });
    }

    const created = await insert("project_files", {
      project_id: project.id,
      filename,
      content,
      mime_type: mimeType || "text/plain",
      size_bytes: sizeBytes
    });

    if (!Array.isArray(created) || created.length === 0) {
      throw new Error("File tidak berhasil dibuat.");
    }

    return res.status(201).json({
      success: true,
      message: "File berhasil dibuat.",
      file: created[0]
    });
  } catch (error) {
    console.error("FILE CREATE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal membuat file."
    });
  }
});
app.get("/api/projects/:projectId/files/:fileId", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const files = await select(
      "project_files",
      `?select=id,project_id,filename,content,mime_type,size_bytes,created_at,updated_at&and=(id.eq.${encodeURIComponent(req.params.fileId)},project_id.eq.${encodeURIComponent(project.id)})&limit=1`
    );

    if (!Array.isArray(files) || files.length === 0) {
      return res.status(404).json({
        success: false,
        message: "File tidak ditemukan."
      });
    }

    return res.json({
      success: true,
      file: files[0]
    });
  } catch (error) {
    console.error("FILE READ ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal membaca file."
    });
  }
});
app.put("/api/projects/:projectId/files/:fileId", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const files = await select(
      "project_files",
      `?select=id,project_id,filename&and=(id.eq.${encodeURIComponent(req.params.fileId)},project_id.eq.${encodeURIComponent(project.id)})&limit=1`
    );

    if (!Array.isArray(files) || files.length === 0) {
      return res.status(404).json({
        success: false,
        message: "File tidak ditemukan."
      });
    }

    const content = String(req.body.content ?? "");
    const mimeType = String(
      req.body.mime_type ?? req.body.mimeType ?? "text/plain"
    ).trim();

    const sizeBytes = Buffer.byteLength(content, "utf8");

    if (sizeBytes > 1024 * 1024) {
      return res.status(413).json({
        success: false,
        message: "Ukuran file maksimal 1 MB."
      });
    }

    const updated = await update(
      "project_files",
      `?id=eq.${encodeURIComponent(files[0].id)}&project_id=eq.${encodeURIComponent(project.id)}`,
      {
        content,
        mime_type: mimeType || "text/plain",
        size_bytes: sizeBytes,
        updated_at: new Date().toISOString()
      }
    );

    if (!Array.isArray(updated) || updated.length === 0) {
      throw new Error("File tidak berhasil diperbarui.");
    }

    return res.json({
      success: true,
      message: "File berhasil diperbarui.",
      file: updated[0]
    });
  } catch (error) {
    console.error("FILE UPDATE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal memperbarui file."
    });
  }
});
app.put("/api/projects/:projectId", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const currentProjects = await select(
      "projects",
      `?select=id,name,description,visibility&and=(id.eq.${encodeURIComponent(project.id)},user_id.eq.${encodeURIComponent(req.user.id)})&limit=1`
    );

    if (!Array.isArray(currentProjects) || currentProjects.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const current = currentProjects[0];

    const name = req.body.name !== undefined
      ? String(req.body.name).trim()
      : current.name;

    const description = req.body.description !== undefined
      ? String(req.body.description).trim()
      : String(current.description || "");

    const visibility = req.body.visibility !== undefined
      ? String(req.body.visibility).trim().toLowerCase()
      : current.visibility;

    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Nama project wajib diisi."
      });
    }

    if (name.length > 100) {
      return res.status(400).json({
        success: false,
        message: "Nama project maksimal 100 karakter."
      });
    }

    if (!["private", "public"].includes(visibility)) {
      return res.status(400).json({
        success: false,
        message: "Visibility project tidak valid."
      });
    }

    if (description.length > 5000) {
      return res.status(400).json({
        success: false,
        message: "Deskripsi project maksimal 5000 karakter."
      });
    }

    const updated = await update(
      "projects",
      `?id=eq.${encodeURIComponent(project.id)}&user_id=eq.${encodeURIComponent(req.user.id)}`,
      {
        name,
        description,
        visibility,
        updated_at: new Date().toISOString()
      }
    );

    if (!Array.isArray(updated) || updated.length === 0) {
      throw new Error("Project tidak berhasil diperbarui.");
    }

    return res.json({
      success: true,
      message: "Project berhasil diperbarui.",
      project: updated[0]
    });
  } catch (error) {
    console.error("PROJECT UPDATE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal memperbarui project."
    });
  }
});
app.delete("/api/projects/:projectId/files/:fileId", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const files = await select(
      "project_files",
      `?select=id,filename&and=(id.eq.${encodeURIComponent(req.params.fileId)},project_id.eq.${encodeURIComponent(project.id)})&limit=1`
    );

    if (!Array.isArray(files) || files.length === 0) {
      return res.status(404).json({
        success: false,
        message: "File tidak ditemukan."
      });
    }

    const deleted = await remove(
      "project_files",
      `?id=eq.${encodeURIComponent(files[0].id)}&project_id=eq.${encodeURIComponent(project.id)}`
    );

    if (!Array.isArray(deleted) || deleted.length === 0) {
      throw new Error("File tidak berhasil dihapus.");
    }

    return res.json({
      success: true,
      message: "File berhasil dihapus.",
      file: deleted[0]
    });
  } catch (error) {
    console.error("FILE DELETE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal menghapus file."
    });
  }
});
app.delete("/api/projects/:projectId", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const deleted = await remove(
      "projects",
      `?id=eq.${encodeURIComponent(project.id)}&user_id=eq.${encodeURIComponent(req.user.id)}`
    );

    if (!Array.isArray(deleted) || deleted.length === 0) {
      throw new Error("Project tidak berhasil dihapus.");
    }

    return res.json({
      success: true,
      message: "Project berhasil dihapus.",
      project: deleted[0]
    });
  } catch (error) {
    console.error("PROJECT DELETE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal menghapus project."
    });
  }
});
app.get("/api/projects/:projectId/versions", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const versions = await select(
      "project_versions",
      `?select=id,project_id,version_number,name,description,created_at&project_id=eq.${encodeURIComponent(project.id)}&order=version_number.desc`
    );

    return res.json({
      success: true,
      project: {
        id: project.id,
        name: project.name,
        slug: project.slug
      },
      versions: Array.isArray(versions) ? versions : []
    });
  } catch (error) {
    console.error("VERSION LIST ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal mengambil daftar versi."
    });
  }
});
app.post("/api/projects/:projectId/versions", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const name = String(req.body.name || "").trim();
    const description = String(req.body.description || "").trim();

    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Nama version wajib diisi."
      });
    }

    if (name.length > 100) {
      return res.status(400).json({
        success: false,
        message: "Nama version maksimal 100 karakter."
      });
    }

    const files = await select(
      "project_files",
      `?select=id,filename,content,mime_type,size_bytes,created_at,updated_at&project_id=eq.${encodeURIComponent(project.id)}&order=filename.asc`
    );

    const snapshot = Array.isArray(files) ? files : [];

    const latest = await select(
      "project_versions",
      `?select=version_number&project_id=eq.${encodeURIComponent(project.id)}&order=version_number.desc&limit=1`
    );

    const lastVersion = Array.isArray(latest) && latest.length > 0
      ? Number(latest[0].version_number) || 0
      : 0;

    const versionNumber = lastVersion + 1;

    const created = await insert("project_versions", {
      project_id: project.id,
      version_number: versionNumber,
      name,
      description,
      snapshot
    });

    if (!Array.isArray(created) || created.length === 0) {
      throw new Error("Version tidak berhasil dibuat.");
    }

    return res.status(201).json({
      success: true,
      message: "Version berhasil dibuat.",
      version: created[0]
    });
  } catch (error) {
    console.error("VERSION CREATE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal membuat version."
    });
  }
});
app.get("/api/projects/:projectId/versions/:versionId", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const versions = await select(
      "project_versions",
      `?select=id,project_id,version_number,name,description,snapshot,created_at&and=(id.eq.${encodeURIComponent(req.params.versionId)},project_id.eq.${encodeURIComponent(project.id)})&limit=1`
    );

    if (!Array.isArray(versions) || versions.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Version tidak ditemukan."
      });
    }

    return res.json({
      success: true,
      project: {
        id: project.id,
        name: project.name,
        slug: project.slug
      },
      version: versions[0]
    });
  } catch (error) {
    console.error("VERSION READ ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal membaca version."
    });
  }
});
app.post("/api/projects/:projectId/versions/:versionId/restore", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    const versions = await select(
      "project_versions",
      `?select=id,project_id,version_number,name,description,snapshot&and=(id.eq.${encodeURIComponent(req.params.versionId)},project_id.eq.${encodeURIComponent(project.id)})&limit=1`
    );

    if (!Array.isArray(versions) || versions.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Version tidak ditemukan."
      });
    }

    const version = versions[0];
    const snapshot = Array.isArray(version.snapshot)
      ? version.snapshot
      : [];

    const currentFiles = await select(
      "project_files",
      `?select=id,filename&project_id=eq.${encodeURIComponent(project.id)}`
    );

    if (Array.isArray(currentFiles)) {
      for (const file of currentFiles) {
        await remove(
          "project_files",
          `?id=eq.${encodeURIComponent(file.id)}&project_id=eq.${encodeURIComponent(project.id)}`
        );
      }
    }

    for (const file of snapshot) {
      await insert("project_files", {
        project_id: project.id,
        filename: file.filename,
        content: String(file.content || ""),
        mime_type: file.mime_type || "text/plain",
        size_bytes: Number(file.size_bytes) || Buffer.byteLength(
          String(file.content || ""),
          "utf8"
        )
      });
    }

    return res.json({
      success: true,
      message: `Project berhasil dipulihkan ke Version ${version.version_number}.`,
      version: {
        id: version.id,
        version_number: version.version_number,
        name: version.name,
        description: version.description
      }
    });
  } catch (error) {
    console.error("VERSION RESTORE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal memulihkan version."
    });
  }
});
app.get("/api/projects/:projectId/versions/compare/:versionId/:otherVersionId", requireAuth, async (req, res) => {
  try {
    const project = await getOwnedProject(
      req.params.projectId,
      req.user.id
    );

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project tidak ditemukan."
      });
    }

    if (req.params.versionId === req.params.otherVersionId) {
      return res.status(400).json({
        success: false,
        message: "Version yang dibandingkan harus berbeda."
      });
    }

    const versions = await select(
      "project_versions",
      `?select=id,project_id,version_number,name,description,snapshot&and=(project_id.eq.${encodeURIComponent(project.id)},id.in.(${encodeURIComponent(req.params.versionId)},${encodeURIComponent(req.params.otherVersionId)}))&order=version_number.asc`
    );

    if (!Array.isArray(versions) || versions.length !== 2) {
      return res.status(404).json({
        success: false,
        message: "Salah satu version tidak ditemukan."
      });
    }

    const firstVersion =
      versions.find(v => v.id === req.params.versionId) || null;

    const secondVersion =
      versions.find(v => v.id === req.params.otherVersionId) || null;

    if (!firstVersion || !secondVersion) {
      return res.status(404).json({
        success: false,
        message: "Version tidak ditemukan."
      });
    }

    const firstSnapshot = Array.isArray(firstVersion.snapshot)
      ? firstVersion.snapshot
      : [];

    const secondSnapshot = Array.isArray(secondVersion.snapshot)
      ? secondVersion.snapshot
      : [];

    const firstFiles = new Map(
      firstSnapshot.map(file => [
        file.filename,
        {
          filename: file.filename,
          content: String(file.content || ""),
          mime_type: file.mime_type || "text/plain",
          size_bytes: Number(file.size_bytes) || 0
        }
      ])
    );

    const secondFiles = new Map(
      secondSnapshot.map(file => [
        file.filename,
        {
          filename: file.filename,
          content: String(file.content || ""),
          mime_type: file.mime_type || "text/plain",
          size_bytes: Number(file.size_bytes) || 0
        }
      ])
    );

    const added = [];
    const removed = [];
    const changed = [];
    const unchanged = [];

    for (const [filename, file] of secondFiles) {
      if (!firstFiles.has(filename)) {
        added.push(file);
        continue;
      }

      const previous = firstFiles.get(filename);

      if (
        previous.content !== file.content ||
        previous.mime_type !== file.mime_type
      ) {
        changed.push({
          filename,
          before: previous,
          after: file
        });
      } else {
        unchanged.push(file);
      }
    }

    for (const [filename, file] of firstFiles) {
      if (!secondFiles.has(filename)) {
        removed.push(file);
      }
    }

    return res.json({
      success: true,
      project: {
        id: project.id,
        name: project.name,
        slug: project.slug
      },
      from: {
        id: firstVersion.id,
        version_number: firstVersion.version_number,
        name: firstVersion.name,
        description: firstVersion.description
      },
      to: {
        id: secondVersion.id,
        version_number: secondVersion.version_number,
        name: secondVersion.name,
        description: secondVersion.description
      },
      summary: {
        added: added.length,
        removed: removed.length,
        changed: changed.length,
        unchanged: unchanged.length
      },
      files: {
        added,
        removed,
        changed,
        unchanged
      }
    });
  } catch (error) {
    console.error("VERSION COMPARE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal membandingkan version."
    });
  }
});
app.get("/api/public/projects/:slug", async (req, res) => {
  try {
    const slug = String(req.params.slug || "").trim().toLowerCase();

    if (!slug) {
      return res.status(400).json({
        success: false,
        message: "Slug project wajib diisi."
      });
    }

    const projects = await select(
      "projects",
      `?select=id,name,slug,description,visibility,created_at,updated_at&slug=eq.${encodeURIComponent(slug)}&visibility=eq.public&limit=1`
    );

    if (!Array.isArray(projects) || projects.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Project public tidak ditemukan."
      });
    }

    const project = projects[0];

    const files = await select(
      "project_files",
      `?select=id,filename,content,mime_type,size_bytes,created_at,updated_at&project_id=eq.${encodeURIComponent(project.id)}&order=filename.asc`
    );

    return res.json({
      success: true,
      project,
      files: Array.isArray(files) ? files : []
    });
  } catch (error) {
    console.error("PUBLIC PROJECT ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Gagal mengambil project public."
    });
  }
});
app.get("/preview/:slug", async (req, res) => {
  try {
    const slug = String(req.params.slug || "").trim().toLowerCase();

    if (!slug) {
      return res.status(400).send("Slug project wajib diisi.");
    }

    const projects = await select(
      "projects",
      `?select=id,name,slug,visibility&slug=eq.${encodeURIComponent(slug)}&visibility=eq.public&limit=1`
    );

    if (!Array.isArray(projects) || projects.length === 0) {
      return res.status(404).send("Project public tidak ditemukan.");
    }

    const project = projects[0];

    const files = await select(
      "project_files",
      `?select=filename,content,mime_type&project_id=eq.${encodeURIComponent(project.id)}&filename=eq.index.html&limit=1`
    );

    if (!Array.isArray(files) || files.length === 0) {
      return res.status(404).send("index.html tidak ditemukan.");
    }

    const file = files[0];

    if (file.mime_type !== "text/html") {
      return res.status(415).send("index.html bukan file HTML.");
    }

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("X-WEBHUB-Project", project.slug);

    return res.send(String(file.content || ""));
  } catch (error) {
    console.error("PROJECT PREVIEW ERROR:", error);

    return res.status(500).send("Gagal menampilkan preview project.");
  }
});
app.get("/project/:slug", async (req, res) => {
  try {
    const slug = String(req.params.slug || "").trim().toLowerCase();

    if (!slug) {
      return res.status(400).send("Slug project wajib diisi.");
    }

    const projects = await select(
      "projects",
      `?select=id,name,slug,visibility&slug=eq.${encodeURIComponent(slug)}&visibility=eq.public&limit=1`
    );

    if (!Array.isArray(projects) || projects.length === 0) {
      return res.status(404).send("Project public tidak ditemukan.");
    }

    const project = projects[0];

    const files = await select(
      "project_files",
      `?select=filename,content,mime_type&project_id=eq.${encodeURIComponent(project.id)}&filename=eq.index.html&limit=1`
    );

    if (!Array.isArray(files) || files.length === 0) {
      return res.status(404).send("index.html tidak ditemukan.");
    }

    const file = files[0];

    if (file.mime_type !== "text/html") {
      return res.status(415).send("index.html bukan file HTML.");
    }

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("X-WEBHUB-Project", project.slug);

    return res.send(String(file.content || ""));
  } catch (error) {
    console.error("PROJECT URL ERROR:", error);
    return res.status(500).send("Gagal menampilkan project.");
  }
});

app.get("/project/:slug/:filename", async (req, res) => {
  try {
    const slug = String(req.params.slug || "").trim().toLowerCase();
    const filename = String(req.params.filename || "").trim();

    if (!slug || !filename) {
      return res.status(400).send("Project dan nama file wajib diisi.");
    }

    if (
      filename.includes("/") ||
      filename.includes("\\") ||
      filename.includes("..")
    ) {
      return res.status(400).send("Nama file tidak valid.");
    }

    const projects = await select(
      "projects",
      `?select=id,name,slug,visibility&slug=eq.${encodeURIComponent(slug)}&visibility=eq.public&limit=1`
    );

    if (!Array.isArray(projects) || projects.length === 0) {
      return res.status(404).send("Project public tidak ditemukan.");
    }

    const project = projects[0];

    const files = await select(
      "project_files",
      `?select=filename,content,mime_type&project_id=eq.${encodeURIComponent(project.id)}&filename=eq.${encodeURIComponent(filename)}&limit=1`
    );

    if (Array.isArray(files) && files.length > 0) {
      const file = files[0];

      res.setHeader(
        "Content-Type",
        String(file.mime_type || "text/plain")
      );
      res.setHeader("X-WEBHUB-Project", project.slug);

      return res.send(String(file.content || ""));
    }

    const storagePath = `webhub-assets/${project.id}/${filename}`;
    const storageObject = await getStorageObject(storagePath);

    if (storageObject.statusCode !== 200) {
      console.log(
        "STORAGE DEBUG:",
        storageObject.statusCode,
        storageObject.contentType
      );

      return res.status(404).send("File tidak ditemukan.");
    }

    res.setHeader(
      "Content-Type",
      storageObject.contentType
    );
    res.setHeader("X-WEBHUB-Project", project.slug);

    return res.send(storageObject.body);
  } catch (error) {
    console.error("PROJECT ASSET ERROR:", error);
    return res.status(500).send("Gagal mengambil asset project.");
  }
});

app.get("/index1000.html", (req, res) => {
  res.sendFile(__dirname + "/index1000.html");
});

app.get("/index2000.html", (req, res) => {
  res.sendFile(__dirname + "/index2000.html");
});

app.get("/index3000.html", (req, res) => {
  res.sendFile(__dirname + "/index3000.html");
});

app.get("/index4000.html", (req, res) => {
  res.sendFile(__dirname + "/index4000.html");
});

app.get("/index5000.html", (req, res) => {
  res.sendFile(__dirname + "/index5000.html");
});

app.get("/index6000.html", (req, res) => {
  res.sendFile(__dirname + "/index6000.html");
});

app.use(express.static(__dirname));

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Endpoint tidak ditemukan."
  });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`WEBHUB server berjalan di port ${PORT}`);
  });
}

module.exports = app;


















