require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();

/*
  For local dev:
  - launcher runs locally
  - backend runs locally
  Later, tighten this to your real domain/origin.
*/
app.use(
  cors({
    origin: true,
    credentials: false,
  })
);

app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = String(process.env.JWT_SECRET || "").trim();
const SUPABASE_URL = String(process.env.SUPABASE_URL || "").trim();
const SUPABASE_SERVICE_ROLE_KEY = String(process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim();

if (!JWT_SECRET || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("Missing required env vars: JWT_SECRET, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

function normalizeUserId(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidVrchatUserId(userId) {
  return /^usr_[a-z0-9-]+$/i.test(userId);
}

function resolvePrimaryRank(groups) {
  if (!Array.isArray(groups) || groups.length === 0) return "User";

  const priority = [
    "owner",
    "admin",
    "administrators",
    "moderator",
    "moderators",
    "vip",
    "beta_tester",
  ];

  const normalized = groups.map((g) => String(g || "").trim().toLowerCase());

  for (const group of priority) {
    if (normalized.includes(group)) {
      return group.replace(/_/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
    }
  }

  return normalized[0].replace(/_/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function buildPermissions(groups) {
  const normalized = Array.isArray(groups)
    ? groups.map((g) => String(g || "").trim().toLowerCase())
    : [];

  const hasAny = (...names) => names.some((name) => normalized.includes(String(name).toLowerCase()));

  return {
    access_users_tab: hasAny("admin", "administrators", "moderator", "moderators"),
    access_permissions_tab: hasAny("admin", "administrators"),
    access_user_logs_tab: hasAny("admin", "administrators", "moderator", "moderators"),
    access_moderate_tab: hasAny("admin", "administrators", "moderator", "moderators"),
    access_bans_tab: hasAny("admin", "administrators"),
    launcher_creator: hasAny("owner", "admin", "administrators"),
  };
}

async function getUserGroups(userId) {
  const { data, error } = await supabase
    .from("group_members")
    .select("group_id")
    .eq("user_id", userId);

  if (error) throw error;

  return (data || [])
    .map((row) => String(row.group_id || "").trim())
    .filter(Boolean);
}

async function getUserModules(userId) {
  const { data, error } = await supabase
    .from("module_ownership")
    .select("module_id,status,expires_at")
    .eq("user_id", userId)
    .eq("status", "active");

  if (error) throw error;

  const now = Date.now();

  return (data || [])
    .filter((row) => {
      if (!row.expires_at) return true;
      const t = Date.parse(String(row.expires_at));
      return Number.isNaN(t) ? true : t > now;
    })
    .map((row) => String(row.module_id || "").trim())
    .filter(Boolean);
}

async function getActiveBan(userId) {
  const { data, error } = await supabase
    .from("bans")
    .select("*")
    .eq("user_id", userId)
    .eq("active", true)
    .limit(25);

  if (error) throw error;

  const now = Date.now();
  const rows = data || [];

  for (const row of rows) {
    if (!row.expires_at) return row;
    const t = Date.parse(String(row.expires_at));
    if (Number.isNaN(t) || t > now) return row;
  }

  return null;
}

async function getDiscordLink(vrchatUserId) {
  const { data, error } = await supabase
    .from("discord_links")
    .select("discord_user_id,vrchat_user_id,created_at")
    .eq("vrchat_user_id", vrchatUserId)
    .limit(1);

  if (error) throw error;
  return (data || [])[0] || null;
}

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
}

function authRequired(req, res, next) {
  try {
    const header = String(req.headers.authorization || "");
    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing bearer token" });
    }

    const token = header.slice("Bearer ".length).trim();
    const decoded = jwt.verify(token, JWT_SECRET);

    req.auth = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function requirePermission(permissionKey) {
  return async (req, res, next) => {
    try {
      const userId = normalizeUserId(req.auth?.user_id);
      if (!userId) {
        return res.status(401).json({ error: "Invalid session" });
      }

      const groups = await getUserGroups(userId);
      const permissions = buildPermissions(groups);

      req.liveGroups = groups;
      req.livePermissions = permissions;

      if (!permissions[permissionKey]) {
        return res.status(403).json({ error: "Forbidden" });
      }

      next();
    } catch (err) {
      console.error("requirePermission error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  };
}

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.post("/auth/verify", async (req, res) => {
  try {
    const authCookie = String(req.body?.auth_cookie || "").trim();
    console.log("auth_cookie length:", authCookie.length);
    console.log("auth_cookie preview:", authCookie ? authCookie.slice(0, 16) + "..." : "(empty)");

    if (!authCookie) {
      return res.status(400).json({ error: "Missing auth cookie" });
    }

    const vrchatResponse = await fetch("https://api.vrchat.cloud/api/1/auth/user", {
        method: "GET",
        headers: {
          "User-Agent": "ELIXRLauncher/1.0 (Render backend)",
          "Cookie": `auth=${encodeURIComponent(authCookie)};`,
          "Accept": "application/json",
        },
      });

    const rawText = await vrchatResponse.text();
    console.log("VRChat auth status:", vrchatResponse.status);
    console.log("VRChat auth raw response:", rawText);

    let vrchatData = {};
    try {
    vrchatData = rawText ? JSON.parse(rawText) : {};
    } catch {
    vrchatData = {};
    }

    if (!vrchatResponse.ok) {
    return res.status(401).json({
        error: "Invalid VRChat session",
        vrchat_status: vrchatResponse.status,
    });
    }

    const userId = normalizeUserId(vrchatData.id);
    const displayName = String(vrchatData.displayName || vrchatData.username || "").trim();

    if (!isValidVrchatUserId(userId)) {
      return res.status(400).json({ error: "Invalid VRChat user id from VRChat API" });
    }

    console.log("Verified VRChat user:", userId, displayName);

    const [groups, modules, activeBan, discordLink] = await Promise.all([
      getUserGroups(userId),
      getUserModules(userId),
      getActiveBan(userId),
      getDiscordLink(userId),
    ]);

    const rank = resolvePrimaryRank(groups);
    const permissions = buildPermissions(groups);

    const token = createToken({
      user_id: userId,
      display_name: displayName || null,
      groups,
      rank,
    });

    return res.json({
      ok: true,
      token,
      profile: {
        user_id: userId,
        display_name: displayName || null,
        rank,
        groups,
        modules,
        permissions,
        discord_linked: !!discordLink,
      },
      ban: activeBan
        ? {
            active: true,
            reason: activeBan.reason || "No reason provided",
            expires_at: activeBan.expires_at || null,
          }
        : {
            active: false,
          },
    });
  } catch (err) {
    console.error("/auth/verify error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/user/profile", authRequired, async (req, res) => {
  try {
    const userId = normalizeUserId(req.auth.user_id);

    const [groups, modules, activeBan, discordLink] = await Promise.all([
      getUserGroups(userId),
      getUserModules(userId),
      getActiveBan(userId),
      getDiscordLink(userId),
    ]);

    const rank = resolvePrimaryRank(groups);
    const permissions = buildPermissions(groups);

    return res.json({
      ok: true,
      profile: {
        user_id: userId,
        display_name: req.auth.display_name || null,
        rank,
        groups,
        modules,
        permissions,
        discord_linked: !!discordLink,
      },
      ban: activeBan
        ? {
            active: true,
            reason: activeBan.reason || "No reason provided",
            expires_at: activeBan.expires_at || null,
          }
        : {
            active: false,
          },
    });
  } catch (err) {
    console.error("/user/profile error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/link/consume", authRequired, async (req, res) => {
  try {
    const code = String(req.body?.code || "").trim().toUpperCase();
    const vrchatUserId = normalizeUserId(req.auth.user_id);

    if (!code) {
      return res.status(400).json({ error: "Missing code" });
    }

    const { data: codeRows, error: codeError } = await supabase
      .from("link_codes")
      .select("id,code,discord_user_id,expires_at,used")
      .eq("code", code)
      .eq("used", false)
      .limit(1);

    if (codeError) throw codeError;

    const found = (codeRows || [])[0];
    if (!found) {
      return res.status(400).json({ error: "Invalid or expired code" });
    }

    if (found.expires_at) {
      const expiresTs = Date.parse(String(found.expires_at));
      if (!Number.isNaN(expiresTs) && expiresTs <= Date.now()) {
        return res.status(400).json({ error: "Invalid or expired code" });
      }
    }

    const discordUserId = String(found.discord_user_id || "").trim();
    if (!discordUserId) {
      return res.status(400).json({ error: "Code missing discord user id" });
    }

    const { data: existingVrRows, error: existingVrError } = await supabase
      .from("discord_links")
      .select("discord_user_id,vrchat_user_id")
      .eq("vrchat_user_id", vrchatUserId)
      .limit(1);

    if (existingVrError) throw existingVrError;

    const existingVr = (existingVrRows || [])[0];
    if (existingVr && String(existingVr.discord_user_id || "") !== discordUserId) {
      return res.status(400).json({ error: "That VRChat account is already linked" });
    }

    const { data: existingDiscordRows, error: existingDiscordError } = await supabase
      .from("discord_links")
      .select("discord_user_id,vrchat_user_id")
      .eq("discord_user_id", discordUserId)
      .limit(1);

    if (existingDiscordError) throw existingDiscordError;

    const existingDiscord = (existingDiscordRows || [])[0];

    if (existingDiscord) {
      const { error: patchError } = await supabase
        .from("discord_links")
        .update({ vrchat_user_id: vrchatUserId })
        .eq("discord_user_id", discordUserId);

      if (patchError) throw patchError;
    } else {
      const { error: insertError } = await supabase
        .from("discord_links")
        .insert({
          discord_user_id: discordUserId,
          vrchat_user_id: vrchatUserId,
        });

      if (insertError) throw insertError;
    }

    const { error: usedError } = await supabase
      .from("link_codes")
      .update({ used: true })
      .eq("id", found.id);

    if (usedError) throw usedError;

    return res.json({
      ok: true,
      message: "Discord linked successfully",
    });
  } catch (err) {
    console.error("/link/consume error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/creator/module", authRequired, requirePermission("launcher_creator"), async (req, res) => {
    try {
      const body = req.body || {};
  
      const id = String(body.id || "").trim().toLowerCase();
      const title = String(body.title || "").trim();
  
      if (!id || !title) {
        return res.status(400).json({ error: "Missing required fields" });
      }
  
      if (!/^[a-z0-9_-]+$/.test(id)) {
        return res.status(400).json({ error: "Invalid id format" });
      }
  
      const { data: existingRows, error: existingError } = await supabase
        .from("launcher_products")
        .select("id")
        .eq("id", id)
        .limit(1);
  
      if (existingError) throw existingError;
  
      if ((existingRows || []).length > 0) {
        return res.status(400).json({ error: "A product with that id already exists" });
      }
  
      const payload = {
        id,
        title,
        subtitle: String(body.subtitle || "").trim(),
        description: String(body.description || "").trim(),
        tag: String(body.tag || "").trim(),
        price: String(body.price || "").trim(),
        image: String(body.image || "").trim(),
        url: String(body.url || "").trim(),
        ownership_id: String(body.ownership_id || id).trim() || id,
        groups: Array.isArray(body.groups) ? body.groups.map(x => String(x || "").trim()).filter(Boolean) : [],
        version: String(body.version || "").trim(),
        zip_url: String(body.zip_url || "").trim(),
        exe_name: String(body.exe_name || "").trim(),
        install_folder: String(body.install_folder || id).trim() || id,
        type: String(body.type || "module").trim().toLowerCase() || "module",
        enabled: Boolean(body.enabled),
        installable: Boolean(body.installable),
        created_by: normalizeUserId(req.auth.user_id),
      };
  
      const { error: insertError } = await supabase
        .from("launcher_products")
        .insert(payload);
  
      if (insertError) throw insertError;
  
      return res.json({
        ok: true,
        message: "Product created successfully",
        product: payload,
      });
    } catch (err) {
      console.error("/creator/module error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/creator/module/update", authRequired, requirePermission("launcher_creator"), async (req, res) => {
    try {
      const body = req.body || {};
  
      const id = String(body.id || "").trim().toLowerCase();
      if (!id) {
        return res.status(400).json({ error: "Missing product id" });
      }
  
      const payload = {
        title: String(body.title || "").trim(),
        subtitle: String(body.subtitle || "").trim(),
        description: String(body.description || "").trim(),
        tag: String(body.tag || "").trim(),
        price: String(body.price || "").trim(),
        image: String(body.image || "").trim(),
        url: String(body.url || "").trim(),
        ownership_id: String(body.ownership_id || id).trim() || id,
        groups: Array.isArray(body.groups) ? body.groups.map(x => String(x || "").trim()).filter(Boolean) : [],
        version: String(body.version || "").trim(),
        zip_url: String(body.zip_url || "").trim(),
        exe_name: String(body.exe_name || "").trim(),
        install_folder: String(body.install_folder || "").trim(),
        type: String(body.type || "module").trim().toLowerCase() || "module",
        enabled: Boolean(body.enabled),
        installable: Boolean(body.installable),
        updated_at: new Date().toISOString(),
      };
  
      const { data, error } = await supabase
        .from("launcher_products")
        .update(payload)
        .eq("id", id)
        .select("id")
        .limit(1);
  
      if (error) throw error;
  
      if (!data || data.length === 0) {
        return res.status(404).json({ error: "Product not found" });
      }
  
      return res.json({
        ok: true,
        message: "Product updated successfully",
      });
    } catch (err) {
      console.error("/creator/module/update error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/products", authRequired, async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("launcher_products")
        .select("*")
        .eq("enabled", true)
        .order("created_at", { ascending: true });
  
      if (error) throw error;
  
      return res.json({
        ok: true,
        products: data || [],
      });
    } catch (err) {
      console.error("/products error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/creator/products", authRequired, requirePermission("launcher_creator"), async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("launcher_products")
        .select("*")
        .order("created_at", { ascending: true });
  
      if (error) throw error;
  
      return res.json({
        ok: true,
        products: data || [],
      });
    } catch (err) {
      console.error("/creator/products error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/creator/module/delete", authRequired, requirePermission("launcher_creator"), async (req, res) => {
    try {
      const id = String(req.body?.id || "").trim().toLowerCase();
  
      if (!id) {
        return res.status(400).json({ error: "Missing product id" });
      }
  
      const { error } = await supabase
        .from("launcher_products")
        .delete()
        .eq("id", id);
  
      if (error) throw error;
  
      return res.json({
        ok: true,
        message: "Product deleted",
      });
    } catch (err) {
      console.error("/creator/module/delete error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });
  
  app.listen(PORT, () => {
    console.log(`ELIXR API listening on port ${PORT}`);
  });
