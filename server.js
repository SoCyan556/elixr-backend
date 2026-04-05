require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.use(cors({ origin: true }));
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = String(process.env.JWT_SECRET || "").trim();
const SUPABASE_URL = String(process.env.SUPABASE_URL || "").trim();
const SUPABASE_SERVICE_ROLE_KEY = String(process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim();

if (!JWT_SECRET || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("Missing env vars");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

function normalize(value) {
  return String(value || "").trim().toLowerCase();
}

function createAccessToken(user) {
  return jwt.sign(
    {
      elixr_user_id: user.id,
      email: user.email,
      username: user.username,
    },
    JWT_SECRET,
    { expiresIn: "15m" }
  );
}

function generateRefreshToken() {
  return crypto.randomBytes(48).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function getUserByLogin(login) {
  const val = normalize(login);

  const { data, error } = await supabase
    .from("elixr_users")
    .select("*")
    .or(`email.eq.${val},username.eq.${val}`)
    .limit(1);

  if (error) throw error;
  return data?.[0] || null;
}

async function getUserGroups(userId) {
  const { data } = await supabase
    .from("elixr_group_members")
    .select("group_id")
    .eq("user_id", userId);

  return (data || []).map(x => x.group_id);
}

function buildPermissions(groups) {
  const g = groups.map(x => x.toLowerCase());

  return {
    launcher_creator: g.includes("admin") || g.includes("administrators"),
  };
}

function authRequired(req, res, next) {
  try {
    const token = String(req.headers.authorization || "").replace("Bearer ", "");
    const decoded = jwt.verify(token, JWT_SECRET);
    req.auth = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid session" });
  }
}

function requirePermission(key) {
  return async (req, res, next) => {
    const groups = await getUserGroups(req.auth.elixr_user_id);
    const perms = buildPermissions(groups);

    if (!perms[key]) {
      return res.status(403).json({ error: "Forbidden" });
    }

    req.groups = groups;
    next();
  };
}

app.get("/health", (req, res) => res.json({ ok: true }));

// =========================
// AUTH
// =========================

app.post("/elixr-auth/register", async (req, res) => {
  try {
    const email = normalize(req.body.email);
    const username = normalize(req.body.username);
    const password = String(req.body.password || "");

    if (!email || !username || password.length < 8) {
      return res.status(400).json({ error: "Invalid input" });
    }

    const hash = await bcrypt.hash(password, 12);

    const { data, error } = await supabase
      .from("elixr_users")
      .insert({
        email,
        username,
        password_hash: hash,
      })
      .select("*")
      .limit(1);

    if (error) throw error;

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Register failed" });
  }
});

app.post("/elixr-auth/login", async (req, res) => {
  try {
    const user = await getUserByLogin(req.body.login);

    if (!user) return res.status(401).json({ error: "Invalid login" });

    const valid = await bcrypt.compare(req.body.password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid login" });

    const access = createAccessToken(user);
    const refresh = generateRefreshToken();

    await supabase.from("elixr_refresh_tokens").insert({
      user_id: user.id,
      token_hash: hashToken(refresh),
      expires_at: new Date(Date.now() + 30 * 86400000).toISOString(),
    });

    return res.json({
      ok: true,
      access_token: access,
      refresh_token: refresh,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Login failed" });
  }
});

app.get("/elixr-auth/me", authRequired, async (req, res) => {
  const user = await getUserByLogin(req.auth.email);
  const groups = await getUserGroups(user.id);

  return res.json({
    ok: true,
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      groups,
    },
  });
});

// =========================
// PRODUCTS
// =========================

app.get("/products", authRequired, async (req, res) => {
  const { data } = await supabase
    .from("launcher_products")
    .select("*")
    .eq("enabled", true);

  res.json({ ok: true, products: data || [] });
});

app.get("/creator/products", authRequired, requirePermission("launcher_creator"), async (req, res) => {
  const { data } = await supabase.from("launcher_products").select("*");
  res.json({ ok: true, products: data || [] });
});

app.post("/creator/module", authRequired, requirePermission("launcher_creator"), async (req, res) => {
  try {
    const payload = req.body;

    const row = {
      ...payload,
      created_by: req.auth.elixr_user_id,
    };

    console.log("CREATE PRODUCT PAYLOAD:", row);

    const { data, error } = await supabase
      .from("launcher_products")
      .insert([row])
      .select();

    if (error) {
      console.error("INSERT ERROR:", error);
      return res.status(500).json({ error: error.message });
    }

    console.log("INSERT SUCCESS:", data);
    res.json({ ok: true, data });
  } catch (err) {
    console.error("SERVER ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/creator/module/update", authRequired, requirePermission("launcher_creator"), async (req, res) => {
  const id = req.body.id;
  await supabase.from("launcher_products").update(req.body).eq("id", id);
  res.json({ ok: true });
});

app.post("/creator/module/delete", authRequired, requirePermission("launcher_creator"), async (req, res) => {
  await supabase.from("launcher_products").delete().eq("id", req.body.id);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`ELIXR API running on ${PORT}`);
});
