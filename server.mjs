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