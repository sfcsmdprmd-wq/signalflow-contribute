import pg from "pg";
import sharp from "sharp";
import express from "express";
import multer from "multer";
import fs from "fs";
import path from "path";
import crypto from "crypto";
const app=express(), PORT=process.env.PORT||3000;
fs.mkdirSync("uploads",{recursive:true});
const upload=multer({dest:"uploads/",limits:{fileSize:250*1024*1024}});
const iconSource=fs.readFileSync("public/contribute-icon.svg");
await Promise.all([[32,"favicon-32-v3.png"],[180,"apple-touch-icon-v3.png"],[192,"icon-192-v3.png"],[512,"icon-512-v3.png"]].map(async([size,name])=>sharp(iconSource).resize(size,size).png().toFile("public/"+name)));
app.use(express.json()); app.use(express.static(path.resolve("public")));
app.get("/inbox-demo",(_req,res)=>res.sendFile(path.resolve("public/inbox-demo.html")));
app.get("/inbox-demo.html",(_req,res)=>res.sendFile(path.resolve("public/inbox-demo.html")));
app.get("/inbox",(_req,res)=>res.sendFile(path.resolve("public/inbox.html")));
app.get("/inbox-desktop-demo",(_req,res)=>res.sendFile(path.resolve("public/inbox-desktop-demo.html")));
app.get("/inbox-desktop-demo.html",(_req,res)=>res.sendFile(path.resolve("public/inbox-desktop-demo.html")));
const destinations=[{"id":"local-news","name":"Local News","notesPrompt":"Optional newsroom details","notesRequired":false,"titleRequired":false,"cartNumbers":["901","902"],"types":["audio"]},{"id":"sport","name":"Sport","notesPrompt":"Optional contributor name","notesRequired":false,"titleRequired":true,"types":["audio"]},{"id":"interviews","name":"Interviews","notesPrompt":"Optional description, contributor name or other details","notesRequired":false,"titleRequired":true,"types":["audio"]},{"id":"photo","name":"Photo upload","notesPrompt":"Description, contributor name or other details","notesRequired":true,"titleRequired":true,"types":["photo"]},{"id":"video","name":"Video upload","notesPrompt":"Description, contributor name or other details","notesRequired":true,"titleRequired":true,"types":["video"]}];
const legacyFolderMap={"news-int":"interviews","news-bul":"local-news","breaking":"local-news","features":"interviews","production":"interviews"};
const mappedFolders=folders=>[...new Set((folders||[]).map(x=>legacyFolderMap[x]||x))];
const ADMIN_EMAIL="dan@blackcountryradio.co.uk";
const db=process.env.DATABASE_URL?new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL.includes("railway.internal")?false:{rejectUnauthorized:false}}):null;
const ready=db?db.query(`CREATE TABLE IF NOT EXISTS contribute_users (id UUID PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL, folders JSONB NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW()); CREATE TABLE IF NOT EXISTS contribute_sessions (token_hash TEXT PRIMARY KEY, user_id UUID REFERENCES contribute_users(id) ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL); CREATE TABLE IF NOT EXISTS contribute_files (id UUID PRIMARY KEY, user_id UUID REFERENCES contribute_users(id), title TEXT NOT NULL, destination TEXT NOT NULL, type TEXT NOT NULL, size BIGINT NOT NULL, delivered_at TIMESTAMPTZ NOT NULL, dropbox_id TEXT NOT NULL); ALTER TABLE contribute_files ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT ''; ALTER TABLE contribute_files ADD COLUMN IF NOT EXISTS inbox_status TEXT NOT NULL DEFAULT 'New';`).catch(e=>{console.error("Database initialization failed",e.message);throw e}):Promise.resolve();
const hashPassword=(password,salt)=>crypto.scryptSync(password,salt,64).toString("hex");
const publicUser=u=>({id:u.id,email:u.email,role:u.role,folders:mappedFolders(u.folders)});
async function session(req,res,next){
 try{await ready;if(!db)return res.status(503).json({error:"Account database is not configured"});
 const token=req.get("Authorization")?.replace(/^Bearer /,"");if(!token)return res.status(401).json({error:"Please sign in"});
 const q=await db.query("SELECT u.* FROM contribute_sessions s JOIN contribute_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW()",[crypto.createHash("sha256").update(token).digest("hex")]);
 if(!q.rows[0])return res.status(401).json({error:"Session expired. Please sign in again"});
 req.user=q.rows[0];next()}catch(e){console.error(e);res.status(503).json({error:"Account service unavailable"})}
}
app.get("/api/auth/status",async(req,res)=>{try{await ready;res.json({configured:!!db,adminEmail:ADMIN_EMAIL})}catch(e){res.status(503).json({error:"Database unavailable"})}});
app.post("/api/auth/bootstrap",async(req,res)=>{
 try{await ready;if(!db||!process.env.ADMIN_SETUP_KEY)return res.status(503).json({error:"Administrator setup unavailable"});
 const count=await db.query("SELECT 1 FROM contribute_users LIMIT 1");if(count.rowCount)return res.status(409).json({error:"Administrator already created"});
 if(req.body.setupKey!==process.env.ADMIN_SETUP_KEY)return res.status(403).json({error:"Incorrect setup key"});
 if(typeof req.body.password!=="string"||req.body.password.length<14||req.body.password.length>128)return res.status(400).json({error:"Password must contain 14–128 characters"});
 const salt=crypto.randomBytes(24).toString("hex");
 await db.query("INSERT INTO contribute_users(id,email,password_hash,salt,role,folders) VALUES($1,$2,$3,$4,$5,$6)",[crypto.randomUUID(),ADMIN_EMAIL,hashPassword(req.body.password,salt),salt,"admin",JSON.stringify(destinations.map(d=>d.id))]);
 res.json({ok:true});
 }catch(e){console.error(e);res.status(503).json({error:"Setup failed"})}
});
app.post("/api/auth/login",async(req,res)=>{
 try{await ready;if(!db)return res.status(503).json({error:"Account database not configured"});
 const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");
 const q=await db.query("SELECT * FROM contribute_users WHERE email=$1",[email]);const u=q.rows[0];
 const salt=u?.salt||"0".repeat(48),actual=hashPassword(password,salt),expected=u?.password_hash||"0".repeat(128);
 if(!u||!crypto.timingSafeEqual(Buffer.from(actual,"hex"),Buffer.from(expected,"hex")))return res.status(401).json({error:"Incorrect email or password"});
 const token=crypto.randomBytes(32).toString("base64url");
 await db.query("INSERT INTO contribute_sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '30 days')",[crypto.createHash("sha256").update(token).digest("hex"),u.id]);
 res.json({token,user:publicUser(u)});
 }catch(e){console.error(e);res.status(503).json({error:"Login unavailable"})}
});
app.post("/api/auth/logout",session,async(req,res)=>{const token=req.get("Authorization").slice(7);await db.query("DELETE FROM contribute_sessions WHERE token_hash=$1",[crypto.createHash("sha256").update(token).digest("hex")]);res.json({ok:true})});

/* Optional Workspace SSO. Legacy password sessions remain operational. */
const identityBase='https://my-signalflow-production.up.railway.app';
app.get('/auth/sso/start',(_req,res)=>res.redirect(identityBase+'/auth/contribute/start'));
app.get('/auth/sso/callback',async(req,res)=>{
  res.set('Cache-Control','no-store');
  if(!process.env.SSO_BRIDGE_SECRET)return res.status(503).send('Workspace sign-in is not configured for Contribute.');
  const ticket=String(req.query.ticket||'');
  if(!/^[a-zA-Z0-9_-]{43}$/.test(ticket))return res.status(400).send('Invalid sign-in link.');
  try{
    await ready;
    const exchange=await fetch(identityBase+'/api/sso/contribute/exchange',{method:'POST',headers:{'Content-Type':'application/json','X-SignalFlow-Bridge':process.env.SSO_BRIDGE_SECRET},body:JSON.stringify({ticket}),signal:AbortSignal.timeout(12000)});
    if(!exchange.ok)return res.status(403).send('Workspace sign-in was rejected or expired. Please return to My SignalFlow and try again.');
    const {email}=await exchange.json();
    if(typeof email!=='string'||!email.toLowerCase().endsWith('@blackcountryradio.co.uk'))return res.status(403).send('Workspace account required.');
    const normalised=email.toLowerCase();
    let user=await db.query('SELECT * FROM contribute_users WHERE email=$1',[normalised]);
    if(!user.rows.length){
      const salt=crypto.randomBytes(24).toString('hex');
      const password=crypto.randomBytes(48).toString('base64url');
      await db.query("INSERT INTO contribute_users(id,email,password_hash,salt,role,folders) VALUES($1,$2,$3,$4,'reporter',$5) ON CONFLICT(email) DO NOTHING",[crypto.randomUUID(),normalised,hashPassword(password,salt),salt,JSON.stringify(['local-news'])]);
      user=await db.query('SELECT * FROM contribute_users WHERE email=$1',[normalised]);
    }
    if(!user.rows.length)return res.status(503).send('Could not prepare Contribute account.');
    const token=crypto.randomBytes(32).toString('base64url');
    await db.query("INSERT INTO contribute_sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '12 hours')",[crypto.createHash('sha256').update(token).digest('hex'),user.rows[0].id]);
    res.cookie('contribute_sso',token,{httpOnly:true,secure:true,sameSite:'lax',path:'/api/auth/sso-session',maxAge:60000});
    res.redirect('/?sso=1');
  }catch(e){console.error('Contribute SSO failed',e.message);res.status(503).send('Workspace sign-in temporarily unavailable. The existing password login is still available.')}
});
app.post('/api/auth/sso-session',async(req,res)=>{
  res.set('Cache-Control','no-store');
  const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('contribute_sso='))?.slice('contribute_sso='.length);
  res.clearCookie('contribute_sso',{httpOnly:true,secure:true,sameSite:'lax',path:'/api/auth/sso-session'});
  if(!token)return res.status(401).json({error:'No pending Workspace sign-in'});
  try{
    await ready;
    const q=await db.query('SELECT u.* FROM contribute_sessions s JOIN contribute_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW()',[crypto.createHash('sha256').update(token).digest('hex')]);
    if(!q.rows.length)return res.status(401).json({error:'Sign-in expired'});
    res.json({token,user:publicUser(q.rows[0])});
  }catch(e){console.error('SSO session handoff failed',e.message);res.status(503).json({error:'Account unavailable'})}
});

const dropboxReady=()=>Boolean(process.env.DROPBOX_APP_KEY&&process.env.DROPBOX_APP_SECRET&&process.env.DROPBOX_REFRESH_TOKEN);
const safeName=s=>String(s||"contribution").replace(/[^a-zA-Z0-9._ -]/g,"_").slice(0,90);
const dropboxFolder=id=>({"local-news":"local news","sport":"sport","interviews":"interviews","photo":"photo","video":"video"})[id];
async function dropboxToken(){
 const auth=Buffer.from(process.env.DROPBOX_APP_KEY+":"+process.env.DROPBOX_APP_SECRET).toString("base64");
 const r=await fetch("https://api.dropboxapi.com/oauth2/token",{method:"POST",headers:{"Authorization":"Basic "+auth,"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"refresh_token",refresh_token:process.env.DROPBOX_REFRESH_TOKEN})});
 if(!r.ok)throw Error("Dropbox token refresh failed: "+r.status);
 return (await r.json()).access_token;
}
async function dropboxUpload(token,local,remote){
 const data=fs.readFileSync(local),arg={path:remote,mode:"add",autorename:true,mute:false};
 const r=await fetch("https://content.dropboxapi.com/2/files/upload",{method:"POST",headers:{"Authorization":"Bearer "+token,"Dropbox-API-Arg":JSON.stringify(arg),"Content-Type":"application/octet-stream"},body:data});
 if(!r.ok)throw Error("Dropbox upload failed: "+r.status+" "+(await r.text()).slice(0,250));
 return r.json();
}
// The initial Dropbox authorisation is gated by a separate operator-held setup key.
const redirect=()=> "https://"+(process.env.RAILWAY_PUBLIC_DOMAIN||"signalflow-contribute-production.up.railway.app")+"/auth/dropbox/callback";
app.get("/auth/dropbox/start",(req,res)=>{
 if(!process.env.DROPBOX_SETUP_KEY)return res.status(503).send("Set DROPBOX_SETUP_KEY in the Contribute Railway service first.");
 if(typeof req.query.key!=="string"||!crypto.timingSafeEqual(Buffer.from(crypto.createHash("sha256").update(req.query.key).digest()),Buffer.from(crypto.createHash("sha256").update(process.env.DROPBOX_SETUP_KEY).digest())))return res.status(403).send("Invalid setup key");
 const expires=Date.now()+600000,nonce=crypto.randomBytes(16).toString("hex"),payload=expires+"."+nonce;
 const sig=crypto.createHmac("sha256",process.env.DROPBOX_SETUP_KEY).update(payload).digest("hex");
 const u=new URL("https://www.dropbox.com/oauth2/authorize");
 u.search=new URLSearchParams({client_id:process.env.DROPBOX_APP_KEY,redirect_uri:redirect(),response_type:"code",token_access_type:"offline",state:payload+"."+sig}).toString();
 res.redirect(u.toString());
});
app.get("/auth/dropbox/callback",async(req,res)=>{
 try{
  if(!process.env.DROPBOX_SETUP_KEY||typeof req.query.state!=="string"||typeof req.query.code!=="string")return res.status(400).send("Invalid callback");
  const [expiry,nonce,sig]=req.query.state.split("."),payload=expiry+"."+nonce;
  const expected=crypto.createHmac("sha256",process.env.DROPBOX_SETUP_KEY).update(payload).digest("hex");
  if(!sig||sig.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected))||Date.now()>Number(expiry))return res.status(403).send("Expired or invalid state");
  const auth=Buffer.from(process.env.DROPBOX_APP_KEY+":"+process.env.DROPBOX_APP_SECRET).toString("base64");
  const r=await fetch("https://api.dropboxapi.com/oauth2/token",{method:"POST",headers:{"Authorization":"Basic "+auth,"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({code:req.query.code,grant_type:"authorization_code",redirect_uri:redirect()})});
  if(!r.ok)throw Error("Dropbox authorisation failed");
  const result=await r.json();if(!result.refresh_token)throw Error("Dropbox did not return a refresh token");
  res.set("Cache-Control","no-store");res.type("html").send('<!doctype html><meta name="referrer" content="no-referrer"><title>Dropbox connected</title><h2>Dropbox authorisation successful</h2><p>Copy this refresh token into a private Railway variable named <b>DROPBOX_REFRESH_TOKEN</b>. Do not share it or commit it to GitHub.</p><textarea readonly style="width:95%;height:110px">'+result.refresh_token.replace(/[&<>"]/g,"")+'</textarea><p>After saving, close this tab. Remove DROPBOX_SETUP_KEY from Railway when finished.</p>');
 }catch(e){console.error("Dropbox OAuth callback failed",e.message);res.status(502).send("Dropbox connection failed. Check the redirect URI and retry.");}
});

app.get("/api/config",session,(req,res)=>res.json({trial:false,user:publicUser(req.user),destinations:destinations.filter(d=>mappedFolders(req.user.folders).includes(d.id))}));
app.get("/api/inbox",session,async(req,res)=>{if(req.user.role!=="admin")return res.status(403).json({error:"Administrator only"});try{const q=await db.query('SELECT f.id,f.title,f.destination,f.type,f.size,f.delivered_at AS "deliveredAt",u.email AS contributor,COALESCE(f.notes,\'\') AS notes,COALESCE(f.inbox_status,\'New\') AS "inboxStatus" FROM contribute_files f LEFT JOIN contribute_users u ON u.id=f.user_id ORDER BY f.delivered_at DESC LIMIT 200');res.set("Cache-Control","no-store");res.json({items:q.rows})}catch(e){console.error(e);res.status(503).json({error:"Inbox unavailable"})}});
app.patch("/api/inbox/:id/status",session,async(req,res)=>{if(req.user.role!=="admin")return res.status(403).json({error:"Administrator only"});if(!["New","Viewed","Used"].includes(req.body?.status))return res.status(400).json({error:"Invalid status"});try{const q=await db.query("UPDATE contribute_files SET inbox_status=$1 WHERE id=$2 RETURNING id,inbox_status AS status",[req.body.status,req.params.id]);if(!q.rowCount)return res.status(404).json({error:"Not found"});res.json(q.rows[0])}catch(e){console.error(e);res.status(503).json({error:"Update failed"})}});
app.get("/api/inbox/:id/media",session,async(req,res)=>{if(req.user.role!=="admin")return res.status(403).json({error:"Administrator only"});try{const q=await db.query("SELECT dropbox_id,type FROM contribute_files WHERE id=$1",[req.params.id]);if(!q.rowCount)return res.status(404).json({error:"File not found"});const token=await dropboxToken();const r=await fetch("https://api.dropboxapi.com/2/files/get_temporary_link",{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({path:q.rows[0].dropbox_id})});if(!r.ok)return res.status(502).json({error:"Dropbox file unavailable or already ingested"});const data=await r.json();res.set("Cache-Control","no-store");res.json({url:data.link,type:q.rows[0].type})}catch(e){console.error("Inbox media",e.message);res.status(503).json({error:"Media unavailable"})}});
app.get("/api/files",session,async(req,res)=>{try{const q=await db.query("SELECT id,title,destination,type,size,delivered_at AS \"deliveredAt\", 'Delivered to Dropbox' AS status FROM contribute_files WHERE user_id=$1 OR $2='admin' ORDER BY delivered_at DESC LIMIT 100",[req.user.id,req.user.role]);res.json(q.rows)}catch(e){res.status(503).json({error:"Files unavailable"})}});
app.get("/api/admin",session,async(req,res)=>{if(req.user.role!=="admin")return res.status(403).json({error:"Administrator only"});const q=await db.query("SELECT id,email,role,folders FROM contribute_users ORDER BY email");res.json({users:q.rows.map(u=>({...u,folders:mappedFolders(u.folders)})),destinations})});
app.post("/api/admin/users",session,async(req,res)=>{
 if(req.user.role!=="admin")return res.status(403).json({error:"Administrator only"});
 const email=String(req.body.email||"").trim().toLowerCase(),password=req.body.password,folders=req.body.folders;
 if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)||typeof password!=="string"||password.length<14||password.length>128||!Array.isArray(folders)||!folders.every(x=>destinations.some(d=>d.id===x)))return res.status(400).json({error:"Valid email, 14+ character password and permitted folders required"});
 const salt=crypto.randomBytes(24).toString("hex");
 try{const q=await db.query("INSERT INTO contribute_users(id,email,password_hash,salt,role,folders) VALUES($1,$2,$3,$4,'reporter',$5) RETURNING id,email,role,folders",[crypto.randomUUID(),email,hashPassword(password,salt),salt,JSON.stringify(folders)]);res.json(q.rows[0])}catch(e){res.status(409).json({error:"Email already registered"})}
});
app.post("/api/upload",session,upload.single("file"),async(req,res)=>{
 const d=destinations.find(x=>x.id===req.body.destination);
 if(!d||!mappedFolders(req.user.folders).includes(d.id)){if(req.file)fs.unlinkSync(req.file.path);return res.status(403).json({error:"Destination not permitted"});}
 const type=req.body.type||"audio"; if(!d.types.includes(type)){if(req.file)fs.unlinkSync(req.file.path);return res.status(403).json({error:"Media type not permitted"});}
 const title=String(req.body.title||"").trim(),notes=String(req.body.notes||"").trim(),cart=String(req.body.cartNumber||"");
 if(d.titleRequired&&!title||d.notesRequired&&!notes||d.cartNumbers&&!d.cartNumbers.includes(cart)){if(req.file)fs.unlinkSync(req.file.path);return res.status(400).json({error:"Please complete the required destination fields"});}
 if(dropboxReady()){
  if(!req.file)return res.status(400).json({error:"File missing"});

  try{
   const token=await dropboxToken(),ext=path.extname(req.file.originalname||"").slice(0,12),name=(cart?cart+"-":"")+Date.now()+"-"+crypto.randomBytes(5).toString("hex")+"-"+safeName(title||"contribution")+ext;
   const receipt=await dropboxUpload(token,req.file.path,"/"+dropboxFolder(d.id)+"/"+name);
   const item={id:crypto.randomUUID(),title:req.body.title||req.file.originalname,notes:req.body.notes||"",destination:d.name,type,size:req.file.size,deliveredAt:new Date().toISOString(),status:"Delivered to Dropbox",mock:false,dropboxId:receipt.id};
   await db.query("INSERT INTO contribute_files(id,user_id,title,destination,type,size,delivered_at,dropbox_id,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",[item.id,req.user.id,item.title,item.destination,item.type,item.size,item.deliveredAt,receipt.id,item.notes]);return res.json(item);
  }catch(e){console.error("Dropbox delivery failed",e.message);return res.status(502).json({error:"Dropbox did not confirm delivery. Please retry."});}
  finally{fs.unlinkSync(req.file.path)}
 }
 if(req.file)fs.unlinkSync(req.file.path);return res.status(503).json({error:"Dropbox is not yet configured"});
});
app.listen(PORT,()=>console.log("SignalFlow Contribute trial listening on "+PORT));