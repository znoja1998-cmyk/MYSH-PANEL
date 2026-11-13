require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("node:crypto");
const db = require("./db");

const app = express();
app.use(helmet());
app.use(express.json({ limit: "20kb" }));
app.use(express.static("public"));
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));

const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) {
  throw new Error("Set JWT_SECRET to a random value of at least 32 characters.");
}
const durations = {
  "1H": 3600, "3H": 10800, "6H": 21600, "12H": 43200,
  "1D": 86400, "3D": 259200, "7D": 604800, "14D": 1209600,
  "30D": 2592000, "60D": 5184000
};
const sha = value => crypto.createHash("sha256").update(value).digest("hex");
const audit = (actor, action, type, id, details={}) =>
  db.prepare("INSERT INTO audit_log(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)")
    .run(actor || null, action, type, String(id ?? ""), JSON.stringify(details));

function auth(req,res,next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\\s+/i, "");
  try {
    const payload = jwt.verify(token, secret);
    const user = db.prepare("SELECT id,username,role,permissions,active FROM users WHERE id=?").get(payload.sub);
    if (!user || !user.active) return res.status(401).json({error:"Account unavailable"});
    req.user = {...user, permissions: JSON.parse(user.permissions || "{}")};
    next();
  } catch { return res.status(401).json({error:"Authentication required"}); }
}
function allow(...roles) {
  return (req,res,next) => roles.includes(req.user.role) ? next() : res.status(403).json({error:"Insufficient permission"});
}
function can(req, permission) {
  if (["owner","admin"].includes(req.user.role)) return true;
  return req.user.role === "seller" && req.user.permissions[permission] === true;
}
function sellerPermission(permission) {
  return (req,res,next) => can(req,permission) ? next() : res.status(403).json({error:"Permission not granted"});
}
function makeKey(type, durationCode) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const part = n => Array.from({length:n}, () => alphabet[crypto.randomInt(alphabet.length)]).join("");
  const prefix = type === "member" ? `MYSH-M-${durationCode}` :
                 type === "test" ? "MYSH-TEST" : "MYSH-ADMIN";
  return `${prefix}-${part(4)}-${part(4)}`;
}

// Create the first owner once, using environment variables. No default password.
const ownerName = process.env.OWNER_USERNAME;
const ownerPassword = process.env.OWNER_PASSWORD;
if (ownerName && ownerPassword && !db.prepare("SELECT id FROM users WHERE role='owner'").get()) {
  if (ownerPassword.length < 12) throw new Error("OWNER_PASSWORD must be at least 12 characters.");
  db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)")
    .run(ownerName, bcrypt.hashSync(ownerPassword, 12), "owner");
}

app.get("/health", (_req,res) => res.json({ok:true, service:"MYSH PANEL API"}));

app.post("/api/login", rateLimit({windowMs:15*60_000,limit:10}), (req,res) => {
  const {username,password} = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") return res.status(400).json({error:"Username and password required"});
  const user = db.prepare("SELECT * FROM users WHERE username=? AND active=1").get(username);
  if (!user || !bcrypt.compareSync(password,user.password_hash)) return res.status(401).json({error:"Invalid credentials"});
  const token = jwt.sign({sub:user.id},secret,{expiresIn:"8h",issuer:"mysh-panel"});
  audit(user.id,"login","user",user.id);
  res.json({token, user:{id:user.id,username:user.username,role:user.role}});
});

app.get("/api/me", auth, (req,res) => res.json({
  id:req.user.id, username:req.user.username, role:req.user.role, permissions:req.user.permissions
}));

// Owner/admin creates accounts. Seller permissions are explicitly selected per account.
app.post("/api/users", auth, allow("owner","admin"), (req,res) => {
  const {username,password,role,permissions={}} = req.body || {};
  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username || "") || typeof password !== "string" || password.length < 12)
    return res.status(400).json({error:"Username must be 3-32 safe characters; password must be at least 12 characters"});
  if (!["admin","seller","member"].includes(role)) return res.status(400).json({error:"Invalid role"});
  const allowed = ["create_keys","view_keys","suspend_keys","manage_customers","view_sales"];
  const clean = {};
  for (const p of allowed) clean[p] = role === "seller" && permissions[p] === true;
  try {
    const result = db.prepare("INSERT INTO users(username,password_hash,role,permissions) VALUES(?,?,?,?)")
      .run(username,bcrypt.hashSync(password,12),role,JSON.stringify(clean));
    audit(req.user.id,"create_user","user",result.lastInsertRowid,{role});
    res.status(201).json({id:result.lastInsertRowid,username,role,permissions:clean});
  } catch { res.status(409).json({error:"Username already exists"}); }
});


// Admin user overview and per-seller permission editor.
app.get("/api/users", auth, allow("owner","admin"), (_req,res) => {
  const users = db.prepare("SELECT id,username,role,permissions,active,created_at FROM users ORDER BY id DESC LIMIT 200").all()
    .map(u => ({...u, permissions: JSON.parse(u.permissions || "{}")}));
  res.json(users);
});

app.patch("/api/users/:id/permissions", auth, allow("owner","admin"), (req,res) => {
  const target = db.prepare("SELECT id,role FROM users WHERE id=?").get(req.params.id);
  if (!target || target.role !== "seller") return res.status(404).json({error:"Seller not found"});
  const allowed = ["create_keys","view_keys","suspend_keys","manage_customers","view_sales"];
  const submitted = req.body?.permissions;
  if (!submitted || typeof submitted !== "object" || Array.isArray(submitted))
    return res.status(400).json({error:"Permissions object required"});
  const clean = {};
  for (const p of allowed) clean[p] = submitted[p] === true;
  db.prepare("UPDATE users SET permissions=? WHERE id=?").run(JSON.stringify(clean),target.id);
  audit(req.user.id,"update_seller_permissions","user",target.id,clean);
  res.json({ok:true,permissions:clean});
});


app.post("/api/keys", auth, sellerPermission("create_keys"), (req,res) => {
  const {type,duration} = req.body || {};
  if (!["member","test","admin"].includes(type)) return res.status(400).json({error:"Invalid key type"});
  if (type === "admin" && !["owner","admin"].includes(req.user.role))
    return res.status(403).json({error:"Only administrators can issue ADMIN keys"});
  if (type === "test" && !["owner","admin"].includes(req.user.role))
    return res.status(403).json({error:"Only administrators can issue TEST keys"});
  if (type === "member" && !durations[duration]) return res.status(400).json({error:"Invalid duration"});
  const durationSeconds = type === "member" ? durations[duration] : null;
  let key;
  for (let i=0;i<5;i++) {
    key = makeKey(type,duration || null);
    if (!db.prepare("SELECT id FROM keys WHERE key_hash=?").get(sha(key))) break;
  }
  const result = db.prepare(`INSERT INTO keys(key_hash,key_prefix,key_type,duration_code,duration_seconds,owner_user_id)
    VALUES(?,?,?,?,?,?)`).run(sha(key),key.split("-").slice(0,3).join("-"),type,duration || null,durationSeconds,req.user.id);
  audit(req.user.id,"create_key","key",result.lastInsertRowid,{type,duration:duration || null});
  // Raw key is returned once only; only its hash is stored.
  res.status(201).json({id:result.lastInsertRowid,key,type,duration:duration || null,status:"unused"});
});

app.get("/api/keys", auth, sellerPermission("view_keys"), (req,res) => {
  const rows = ["owner","admin"].includes(req.user.role)
    ? db.prepare("SELECT id,key_prefix,key_type,duration_code,status,owner_user_id,bound_hwid_hash,activated_at,expires_at,created_at FROM keys ORDER BY id DESC LIMIT 200").all()
    : db.prepare("SELECT id,key_prefix,key_type,duration_code,status,owner_user_id,bound_hwid_hash,activated_at,expires_at,created_at FROM keys WHERE owner_user_id=? ORDER BY id DESC LIMIT 200").all(req.user.id);
  res.json(rows);
});

// Activation endpoint: HWID is hashed and never returned. The first activation binds the key.
app.post("/api/activate", (req,res) => {
  const {key,hwid} = req.body || {};
  if (typeof key !== "string" || typeof hwid !== "string" || hwid.length < 8 || hwid.length > 256)
    return res.status(400).json({error:"Valid key and device identifier required"});
  const row = db.prepare("SELECT * FROM keys WHERE key_hash=?").get(sha(key));
  if (!row || ["suspended","revoked","expired"].includes(row.status)) return res.status(403).json({error:"Key unavailable"});
  const hwidHash = sha(hwid);
  const now = new Date();
  if (row.bound_hwid_hash && row.bound_hwid_hash !== hwidHash) return res.status(403).json({error:"Key is bound to another device"});
  if (row.key_type === "member" && row.status === "unused") {
    const expires = new Date(now.getTime() + row.duration_seconds * 1000).toISOString();
    db.prepare("UPDATE keys SET bound_hwid_hash=?,status='active',activated_at=?,expires_at=? WHERE id=?")
      .run(hwidHash,now.toISOString(),expires,row.id);
  } else if (!row.bound_hwid_hash) {
    db.prepare("UPDATE keys SET bound_hwid_hash=?,status='active',activated_at=? WHERE id=?")
      .run(hwidHash,now.toISOString(),row.id);
  }
  const current = db.prepare("SELECT expires_at,status FROM keys WHERE id=?").get(row.id);
  if (current.expires_at && new Date(current.expires_at) <= now) {
    db.prepare("UPDATE keys SET status='expired' WHERE id=?").run(row.id);
    return res.status(403).json({error:"Key expired"});
  }
  res.json({ok:true,status:current.status,expiresAt:current.expires_at});
});

app.post("/api/keys/:id/suspend", auth, allow("owner","admin"), (req,res) => {
  const result = db.prepare("UPDATE keys SET status='suspended' WHERE id=? AND status IN ('unused','active')").run(req.params.id);
  if (!result.changes) return res.status(404).json({error:"Key not found or cannot be suspended"});
  audit(req.user.id,"suspend_key","key",req.params.id);
  res.json({ok:true});
});
app.post("/api/keys/:id/revoke", auth, allow("owner","admin"), (req,res) => {
  const result = db.prepare("UPDATE keys SET status='revoked' WHERE id=? AND status!='revoked'").run(req.params.id);
  if (!result.changes) return res.status(404).json({error:"Key not found"});
  audit(req.user.id,"revoke_key","key",req.params.id);
  res.json({ok:true});
});


app.post("/api/keys/:id/reset-hwid", auth, allow("owner","admin"), (req,res) => {
  const result = db.prepare("UPDATE keys SET bound_hwid_hash=NULL,status=CASE WHEN key_type='member' AND expires_at IS NOT NULL AND expires_at<=? THEN 'expired' ELSE 'unused' END,activated_at=NULL WHERE id=? AND status NOT IN ('revoked','suspended')")
    .run(new Date().toISOString(), req.params.id);
  if (!result.changes) return res.status(404).json({error:"Key not found or unavailable"});
  audit(req.user.id,"reset_hwid","key",req.params.id);
  res.json({ok:true});
});

app.use((err,_req,res,_next) => {
  console.error(err);
  res.status(500).json({error:"Internal server error"});
});
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`MYSH PANEL API listening on ${port}`));
