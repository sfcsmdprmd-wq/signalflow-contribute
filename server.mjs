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
const users=[{id:"trial",name:"Trial Reporter",email:"reporter@signalflow.local",role:"News Team",folders:["news-int","news-bul","breaking","features"]}];
const files=[];
const dropboxReady=()=>Boolean(process.env.DROPBOX_APP_KEY&&process.env.DROPBOX_APP_SECRET&&process.env.DROPBOX_REFRESH_TOKEN&&process.env.CONTRIBUTE_UPLOAD_KEY);
const safeName=s=>String(s||"contribution").replace(/[^a-zA-Z0-9._ -]/g,"_").slice(0,90);
const dropboxFolder=id=>({ "news-int":"News/Interviews","news-bul":"News/Bulletins","breaking":"Breaking News","sport":"Sport","features":"Features","production":"Production" })[id];
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
app.get("/api/config",(req,res)=>res.json({trial:!dropboxReady(),user:users[0],destinations:destinations.filter(d=>users[0].folders.includes(d.id))}));
app.get("/api/files",(req,res)=>res.json(files));
app.get("/api/admin",(req,res)=>res.json({users,destinations}));
app.post("/api/upload",upload.single("file"),async(req,res)=>{
 const d=destinations.find(x=>x.id===req.body.destination);
 if(!d||!users[0].folders.includes(d.id)){if(req.file)fs.unlinkSync(req.file.path);return res.status(403).json({error:"Destination not permitted"});}
 const type=req.body.type||"audio"; if(!d.types.includes(type)){if(req.file)fs.unlinkSync(req.file.path);return res.status(403).json({error:"Media type not permitted"});}
 if(dropboxReady()){
  if(!req.file)return res.status(400).json({error:"File missing"});
  if(!process.env.CONTRIBUTE_UPLOAD_KEY||req.get("X-Contribute-Key")!==process.env.CONTRIBUTE_UPLOAD_KEY){fs.unlinkSync(req.file.path);return res.status(401).json({error:"Reporter authorisation required"});}
  try{
   const token=await dropboxToken(),ext=path.extname(req.file.originalname||"").slice(0,12),name=Date.now()+"-"+crypto.randomBytes(5).toString("hex")+"-"+safeName(req.body.title||"contribution")+ext;
   const receipt=await dropboxUpload(token,req.file.path,"/"+dropboxFolder(d.id)+"/"+name);
   const item={id:crypto.randomUUID(),title:req.body.title||req.file.originalname,notes:req.body.notes||"",destination:d.name,type,size:req.file.size,deliveredAt:new Date().toISOString(),status:"Delivered to Dropbox",mock:false,dropboxId:receipt.id};
   files.unshift(item);return res.json(item);
  }catch(e){console.error("Dropbox delivery failed",e.message);return res.status(502).json({error:"Dropbox did not confirm delivery. Please retry."});}
  finally{fs.unlinkSync(req.file.path)}
 }
 const item={id:crypto.randomUUID(),title:req.body.title||req.file?.originalname||"Untitled",notes:req.body.notes||"",destination:d.name,type,size:req.file?.size||0,deliveredAt:new Date().toISOString(),status:"Trial delivered",mock:true};
 if(req.file)fs.unlinkSync(req.file.path);files.unshift(item); res.json(item);
});
app.listen(PORT,()=>console.log("SignalFlow Contribute trial listening on "+PORT));