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
{id:"news-int",name:"News / Interviews",types:["audio","photo","video"]},
{id:"news-bul",name:"News / Bulletins",types:["audio"]},
{id:"breaking",name:"Breaking News",types:["audio","photo","video"]},
{id:"sport",name:"Sport",types:["audio","photo","video"]},
{id:"features",name:"Features",types:["audio","photo","video"]},
{id:"production",name:"Production",types:["audio"]}
];
const users=[{id:"trial",name:"Trial Reporter",email:"reporter@signalflow.local",role:"News Team",folders:["news-int","news-bul","breaking","features"]}];
const files=[];
app.get("/api/config",(req,res)=>res.json({trial:true,user:users[0],destinations:destinations.filter(d=>users[0].folders.includes(d.id))}));
app.get("/api/files",(req,res)=>res.json(files));
app.get("/api/admin",(req,res)=>res.json({users,destinations}));
app.post("/api/upload",upload.single("file"),(req,res)=>{
 const d=destinations.find(x=>x.id===req.body.destination);
 if(!d||!users[0].folders.includes(d.id)){if(req.file)fs.unlinkSync(req.file.path);return res.status(403).json({error:"Destination not permitted"});}
 const type=req.body.type||"audio"; if(!d.types.includes(type)){if(req.file)fs.unlinkSync(req.file.path);return res.status(403).json({error:"Media type not permitted"});}
 const item={id:crypto.randomUUID(),title:req.body.title||req.file?.originalname||"Untitled",notes:req.body.notes||"",destination:d.name,type,size:req.file?.size||0,deliveredAt:new Date().toISOString(),status:"Trial delivered",mock:true};
 files.unshift(item); res.json(item);
});
app.listen(PORT,()=>console.log("SignalFlow Contribute trial listening on "+PORT));