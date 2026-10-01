import pg from "pg";
import express from "express";
import multer from "multer";
import fs from "fs";
import path from "path";
import crypto from "crypto";
const app=express(), PORT=process.env.PORT||3000;
fs.mkdirSync("uploads",{recursive:true});
const upload=multer({dest:"uploads/",limits:{fileSize:250*1024*1024}});
app.use(express.json()); app.use(express.static("public"));
const destinations=[
{id:"news-int",name:"News / Interviews",notesPrompt:"Include the interviewee’s name, role and a brief summary of the interview.",notesHelp:"Mention any particularly useful quotes or time-sensitive information.",notesRequired:false,types:["audio","photo","video"]},
{id:"news-bul",name:"News / Bulletins",notesPrompt:"Include the bulletin time, main stories covered and any important information for the newsreader.",notesHelp:"Include any updates or corrections the newsroom needs to know.",notesRequired:false,types:["audio"]},
{id:"breaking",name:"Breaking News",notesPrompt:"What happened, where and when? Include sources and any details requiring verification.",notesHelp:"Clearly identify any information that is not yet confirmed.",notesRequired:false,types:["audio","photo","video"]},
{id:"sport",name:"Sport",notesPrompt:"Include the teams or event, score if relevant, and a brief summary.",notesHelp:"Add any relevant names or key moments.",notesRequired:false,types:["audio","photo","video"]},
{id:"features",name:"Features",notesPrompt:"Summarise the feature and identify any contributors.",notesHelp:"Add context that will help producers use this material.",notesRequired:false,types:["audio","photo","video"]},
{id:"production",name:"Production",notesPrompt:"Describe this recording and how it should be used.",notesHelp:"Include any relevant production instructions.",notesRequired:false,types:["audio"]}
];
const ADMIN_EMAIL="dan@blackcountryradio.co.uk";
const db=process.env.DATABASE_URL?new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL.includes("railway.internal")?false:{rejectUnauthorized:false}}):null;
const ready=db?db.query(`CREATE TABLE IF NOT EXISTS contribute_users (id UUID PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL, folders JSONB NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW()); CREATE TABLE IF NOT EXISTS contribute_sessions (token_hash TEXT PRIMARY KEY, user_id UUID REFERENCES contribute_users(id) ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL); CREATE TABLE IF NOT EXISTS contribute_files (id UUID PRIMARY KEY, user_id UUID REFERENCES contribute_users(id), title TEXT NOT NULL, destination TEXT NOT NULL, type TEXT NOT NULL, size BIGINT NOT NULL, delivered_at TIMESTAMPTZ NOT NULL, dropbox_id TEXT NOT NULL);`).catch(e=>{console.error("Database initialization failed",e.message);throw e}):Promise.resolve();
const hashPassword=(password,salt)=>crypto.scryptSync(password,salt,64).toString("hex");
const publicUser=u=>({id:u.id,email:u.email,role:u.role,folders:u.folders});
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
 await db.query("INSERT INTO contribute_users(id,email,password_hash,salt,role,folders) VALUES($1,$2,$3,$4,$5,$6)",[crypto.randomUUID(),ADMIN_EMAIL,hashPassword(req.body.password,salt),salt,"admin",destinations.map(d=>d.id)]);
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
app.post("/api/upload",session,upload.single("file"),async(req,res)=>{
 const d=destinations.find(x=>x.id===req.body.destination);
 if(!d||!req.user.folders.includes(d.id)){if(req.file)fs.unlinkSync(req.file.path);return res.status(403).json({error:"Destination not permitted"});}
 const type=req.body.type||"audio"; if(!d.types.includes(type)){if(req.file)fs.unlinkSync(req.file.path);return res.status(403).json({error:"Media type not permitted"});}
 if(dropboxReady()){
  if(!req.file)return res.status(400).json({error:"File missing"});

  try{
   const token=await dropboxToken(),ext=path.extname(req.file.originalname||"").slice(0,12),name=Date.now()+"-"+crypto.randomBytes(5).toString("hex")+"-"+safeName(req.body.title||"contribution")+ext;
   const receipt=await dropboxUpload(token,req.file.path,"/"+dropboxFolder(d.id)+"/"+name);
   const item={id:crypto.randomUUID(),title:req.body.title||req.file.originalname,notes:req.body.notes||"",destination:d.name,type,size:req.file.size,deliveredAt:new Date().toISOString(),status:"Delivered to Dropbox",mock:false,dropboxId:receipt.id};
   await db.query("INSERT INTO contribute_files(id,user_id,title,destination,type,size,delivered_at,dropbox_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",[item.id,req.user.id,item.title,item.destination,item.type,item.size,item.deliveredAt,receipt.id]);return res.json(item);
  }catch(e){console.error("Dropbox delivery failed",e.message);return res.status(502).json({error:"Dropbox did not confirm delivery. Please retry."});}
  finally{fs.unlinkSync(req.file.path)}
 }
 if(req.file)fs.unlinkSync(req.file.path);return res.status(503).json({error:"Dropbox is not yet configured"});
});
app.listen(PORT,()=>console.log("SignalFlow Contribute trial listening on "+PORT));