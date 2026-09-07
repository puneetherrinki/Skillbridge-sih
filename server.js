const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const ROOT = path.join(__dirname, '..');
const FRONTEND = path.join(ROOT, 'frontend');
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'runtime.json');
const SEED_FILE = path.join(DATA_DIR, 'seed-data.json');
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) {
  console.error('JWT_SECRET must be set and at least 32 characters long.');
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true });

function clone(x) { return JSON.parse(JSON.stringify(x)); }
function loadData() {
  if (!fs.existsSync(DATA_FILE)) fs.copyFileSync(SEED_FILE, DATA_FILE);
  const d=JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  d.assessmentAttempts ??= [];
  d.revokedTokens ??= {};
  return d;
}
let db = loadData();
function save() { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
function id(type) { const n = db.next[type] || 1; db.next[type] = n + 1; return n; }
function legacyHashPassword(p) { return crypto.createHash('sha256').update(String(p)).digest('hex'); }
function hashPassword(p, salt) {
  const s=salt || crypto.randomBytes(16).toString('hex');
  const derived=crypto.scryptSync(String(p),s,64).toString('hex');
  return `scrypt$${s}$${derived}`;
}
function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  if (stored.startsWith('scrypt$')) {
    const [,salt,derived]=stored.split('$');
    if(!salt||!derived) return false;
    const actual=crypto.scryptSync(String(password),salt,64).toString('hex');
    return actual.length===derived.length && crypto.timingSafeEqual(Buffer.from(actual),Buffer.from(derived));
  }
  return legacyHashPassword(password)===stored;
}
function signToken(user) {
  const jti=crypto.randomBytes(16).toString('hex');
  const payload = Buffer.from(JSON.stringify({ id:user.id, role:user.role, name:user.name, email:user.email, jti, exp:Date.now()+2*60*60*1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function userFromToken(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  const [p,sig] = h.slice(7).split('.');
  if (!p || !sig) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try { const x=JSON.parse(Buffer.from(p,'base64url').toString()); if(!x.jti || db.revokedTokens[x.jti] || x.exp<=Date.now()) return null; return x; } catch { return null; }
}
function requireAuth(req,res,roles) {
  const u=userFromToken(req);
  if (!u) { json(res,401,{error:'Authentication required.'}); return null; }
  if (roles && !roles.includes(u.role)) { json(res,403,{error:'Permission denied.'}); return null; }
  return u;
}
function json(res,status,data) { const body=JSON.stringify(data); res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"}); res.end(body); }
function notFound(res){json(res,404,{error:'API route not found.'});}
function readBody(req){return new Promise((resolve,reject)=>{let b='';req.on('data',c=>{b+=c;if(b.length>1e6){const e=new Error('Request body is too large.');e.statusCode=413;req.destroy(e);}});req.on('end',()=>{try{resolve(b?JSON.parse(b):{})}catch(e){e.statusCode=400;reject(e)}});req.on('error',reject)})}
function publicUser(u){return {id:u.id,role:u.role,name:u.name,email:u.email};}
function findUserByEmail(email){return db.users.find(u=>u.email===String(email||'').trim().toLowerCase());}
function text(v,max){return typeof v==='string' ? v.trim().slice(0,max) : ''; }
function validEmail(v){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v||'').trim());}
function validPassword(v){return typeof v==='string' && v.length>=8 && v.length<=128;}
const loginAttempts=new Map();
function rateLimited(key){const now=Date.now(), a=loginAttempts.get(key)||[]; const fresh=a.filter(t=>now-t<15*60*1000); if(fresh.length>=10){loginAttempts.set(key,fresh);return true;} fresh.push(now);loginAttempts.set(key,fresh);return false;}
function clearRateLimit(key){loginAttempts.delete(key);}
function issueAssessmentAttempt(studentId,role,qs){const now=Date.now(), attempt={id:crypto.randomBytes(12).toString('hex'),studentId,role,questionIds:qs.map(q=>q.id),startedAt:new Date(now).toISOString(),expiresAt:new Date(now+10*60*1000).toISOString(),status:'active'};db.assessmentAttempts.push(attempt);save();return attempt;}
const roles=['Full Stack Developer','Frontend Developer','Backend Developer','Python Developer','Java Developer','Data Analyst','Cloud Engineer','Software Developer'];
const aliases={'full stack developer':'Full Stack Developer','frontend developer':'Frontend Developer','front-end developer':'Frontend Developer','backend developer':'Backend Developer','back-end developer':'Backend Developer','python developer':'Python Developer','java developer':'Java Developer','data analyst':'Data Analyst','cloud engineer':'Cloud Engineer','software developer':'Software Developer'};
function normRole(x){const k=String(x||'').trim().toLowerCase();return aliases[k]||String(x||'').trim()||'Software Developer';}
function skillById(i){return db.skills.find(s=>s.id===Number(i));}
function analyze(studentId,resultId){
  const result=db.assessments.find(x=>x.id===Number(resultId)&&x.studentId===studentId); if(!result) return null;
  const p=db.studentProfiles[String(studentId)]||{}; const role=normRole(result.role||p.careerGoal);
  const details=(db.resultSkills[String(result.id)]||[]).map(x=>{const s=skillById(x.skillId);return {...x,name:s?.name||'Skill',category:s?.category||'General'}}).sort((a,b)=>a.level-b.level);
  const strengths=details.filter(x=>x.level>=4).map(x=>({skill:x.name,level:x.level,score:Math.round(x.correct/x.total*100),reason:`Strong performance: ${x.correct}/${x.total} correct.`}));
  const gaps=details.filter(x=>x.level<4).map(x=>({skill:x.name,level:x.level,score:Math.round(x.correct/x.total*100),priority:x.level<=2?'High':'Medium',reason:x.level<=2?'This is a significant gap for the selected role.':'This skill needs more practice before interview readiness.'}));
  const readiness=Math.max(0,Math.min(100,Math.round(result.score/result.total*100)));
  const level=readiness>=85?'Interview Ready':readiness>=70?'Nearly Ready':readiness>=50?'Developing':'Foundation Stage';
  const roadmap=gaps.map((g,i)=>({order:i+1,title:`Strengthen ${g.skill}`,description:`Learn core ${g.skill} concepts, complete 2 guided exercises, then build one small ${role} project feature using ${g.skill}.`,priority:g.priority}));
  const summary=`For the ${role} path, your assessment score is ${readiness}%. You are currently at the ${level} stage. Focus first on ${gaps.slice(0,3).map(x=>x.skill).join(', ')||'advanced practice'} while maintaining your stronger skills.`;
  const report={id:id('report'),studentId,resultId:result.id,role,readiness,level,summary,strengths,gaps,roadmap,createdAt:new Date().toISOString()};
  db.aiReports[String(studentId)]=report;
  const existing=db.roadmaps[String(studentId)]||[];
  for(const x of roadmap) if(!existing.some(r=>r.title===x.title&&!r.completed)) existing.push({id:id('roadmap'),studentId,title:x.title,description:x.description,priority:x.priority,completed:false});
  db.roadmaps[String(studentId)]=existing; save(); return report;
}
function studentMe(uid){
  const u=db.users.find(x=>x.id===uid), p=db.studentProfiles[String(uid)]||{}; const skillMap=db.studentSkills[String(uid)]||{};
  return {profile:{id:u.id,name:u.name,email:u.email,...p},skills:Object.entries(skillMap).map(([sid,level])=>{const s=skillById(sid);return {id:s.id,name:s.name,category:s.category,level}}).sort((a,b)=>a.category.localeCompare(b.category)||a.name.localeCompare(b.name)),results:db.assessments.filter(x=>x.studentId===uid).sort((a,b)=>b.id-a.id).map(x=>({id:x.id,score:x.score,total:x.total,assessedAt:x.assessedAt}))};
}
function internshipView(i){const u=db.users.find(x=>x.id===i.companyId);const cp=db.companyProfiles[String(i.companyId)]||{};return {...i,companyName:u?.name||'',industry:cp.industry||'',skills:i.skills.map(x=>({skillId:x.skillId,name:skillById(x.skillId)?.name,requiredLevel:x.requiredLevel}))};}
function matchInternships(uid){const have=db.studentSkills[String(uid)]||{};return db.internships.filter(i=>i.status==='open').map(i=>{const req=i.skills||[];let ok=0;const gaps=[];for(const x of req){const current=have[String(x.skillId)]||0;if(current>=x.requiredLevel)ok++;else gaps.push({skillId:x.skillId,current,required:x.requiredLevel,skill:skillById(x.skillId)?.name})}return {...internshipView(i),matchScore:req.length?Math.round(ok/req.length*100):0,gaps};}).sort((a,b)=>b.matchScore-a.matchScore);}

async function handleApi(req,res,u){
  const url=new URL(req.url,'http://localhost'); const p=url.pathname; const method=req.method;
  try {
    if(p==='/api/health'&&method==='GET') return json(res,200,{ok:true,service:'SkillBridge Runtime API',storage:'JSON'});
    if(p==='/api/auth/login'&&method==='POST'){const b=await readBody(req), email=text(b.email,254).toLowerCase(), key=(req.socket.remoteAddress||'unknown')+'|'+email;if(rateLimited(key))return json(res,429,{error:'Too many login attempts. Please try again later.'});const x=findUserByEmail(email);if(!x||!verifyPassword(b.password||'',x.passwordHash))return json(res,401,{error:'Invalid email or password.'});clearRateLimit(key);if(!String(x.passwordHash).startsWith('scrypt$')){x.passwordHash=hashPassword(b.password);save();}return json(res,200,{token:signToken(x),user:publicUser(x)});}
    if(p==='/api/auth/register/student'&&method==='POST'){const b=await readBody(req);const name=text(b.name,80),email=text(b.email,254).toLowerCase(),password=b.password;if(!name||!validEmail(email)||!validPassword(password))return json(res,400,{error:'Use a valid name, email, and password of 8–128 characters.'});if(findUserByEmail(email))return json(res,409,{error:'An account with that email already exists.'});const cgpa=Number(b.cgpa);if(b.cgpa!==undefined&&b.cgpa!==''&&(!Number.isFinite(cgpa)||cgpa<0||cgpa>10))return json(res,400,{error:'CGPA must be between 0 and 10.'});const x={id:id('user'),role:'student',name,email,passwordHash:hashPassword(password)};db.users.push(x);db.studentProfiles[String(x.id)]={college:text(b.college,120),branch:text(b.branch,80),year:text(b.year,40),cgpa:Number.isFinite(cgpa)?cgpa:0,careerGoal:text(b.careerGoal,100),bio:''};db.studentSkills[String(x.id)]={};save();return json(res,201,{token:signToken(x),user:publicUser(x)});}
    if(p==='/api/auth/register/company'&&method==='POST'){const b=await readBody(req);const name=text(b.name,100),email=text(b.email,254).toLowerCase(),password=b.password;if(!name||!validEmail(email)||!validPassword(password))return json(res,400,{error:'Use a valid company name, email, and password of 8–128 characters.'});if(findUserByEmail(email))return json(res,409,{error:'A company account with that email already exists.'});const x={id:id('user'),role:'company',name,email,passwordHash:hashPassword(password)};db.users.push(x);db.companyProfiles[String(x.id)]={industry:text(b.industry,100),website:text(b.website,200),location:text(b.location,120),description:text(b.description,1000)};save();return json(res,201,{token:signToken(x),user:publicUser(x)});}

    if(p==='/api/auth/logout'&&method==='POST'){u=userFromToken(req);if(u){db.revokedTokens[u.jti]=Date.now();save();}return json(res,200,{message:'Logged out.'});}

    if(p==='/api/skills'&&method==='GET') return json(res,200,db.skills);
    if(p==='/api/students/me'&&method==='GET'){u=requireAuth(req,res,['student']);if(!u)return;return json(res,200,studentMe(u.id));}
    if(p==='/api/students/me'&&method==='PUT'){u=requireAuth(req,res,['student']);if(!u)return;const b=await readBody(req);const x=db.users.find(v=>v.id===u.id),p0=db.studentProfiles[String(u.id)]||{},cgpa=Number(b.cgpa);if(!text(b.name,80)||!Number.isFinite(cgpa)||cgpa<0||cgpa>10)return json(res,400,{error:'Name is required and CGPA must be between 0 and 10.'});x.name=text(b.name,80);db.studentProfiles[String(u.id)]={...p0,college:text(b.college,120),branch:text(b.branch,80),year:text(b.year,40),cgpa,careerGoal:text(b.careerGoal,100),bio:text(b.bio,1000)};save();return json(res,200,{message:'Profile updated.'});}
    if(p==='/api/students/roadmap'&&method==='GET'){u=requireAuth(req,res,['student']);if(!u)return;return json(res,200,db.roadmaps[String(u.id)]||[]);}
    if(p==='/api/students/roadmap'&&method==='POST'){u=requireAuth(req,res,['student']);if(!u)return;const b=await readBody(req);if(!b.title||!b.description)return json(res,400,{error:'Task title and description are required.'});const x={id:id('roadmap'),studentId:u.id,title:b.title,description:b.description,priority:b.priority||'medium',completed:false};(db.roadmaps[String(u.id)]??=[]).push(x);save();return json(res,201,x);}
    const rm=p.match(/^\/api\/students\/roadmap\/(\d+)$/);if(rm&&method==='PATCH'){u=requireAuth(req,res,['student']);if(!u)return;const b=await readBody(req),arr=db.roadmaps[String(u.id)]||[],x=arr.find(v=>v.id===Number(rm[1]));if(!x)return json(res,404,{error:'Roadmap item not found.'});x.completed=!!b.completed;save();return json(res,200,{message:'Roadmap updated.'});}

    if(p==='/api/assessments/roles'&&method==='GET'){u=requireAuth(req,res,['student']);if(!u)return;return json(res,200,roles);}
    if(p==='/api/assessments/questions'&&method==='GET'){u=requireAuth(req,res,['student']);if(!u)return;const requested=url.searchParams.get('role');if(!roles.includes(normRole(requested)))return json(res,400,{error:'Select a supported assessment role.'});const role=normRole(requested),q=db.questions.filter(x=>x.role===role);const attempt=issueAssessmentAttempt(u.id,role,q);return json(res,200,{attemptId:attempt.id,startedAt:attempt.startedAt,expiresAt:attempt.expiresAt,role,questions:q.map(x=>({id:x.id,role:x.role,skillId:x.skillId,skill:skillById(x.skillId)?.name||'General',question:x.question,options:clone(x.options)}))});}
    if(p==='/api/assessments/submit'&&method==='POST'){u=requireAuth(req,res,['student']);if(!u)return;const b=await readBody(req),answers=b.answers&&typeof b.answers==='object'&&!Array.isArray(b.answers)?b.answers:{},role=normRole(b.role),attempt=db.assessmentAttempts.find(a=>a.id===String(b.attemptId)&&a.studentId===u.id);if(!attempt||attempt.status!=='active')return json(res,400,{error:'Assessment attempt is invalid or already submitted.'});if(attempt.role!==role)return json(res,400,{error:'Assessment role does not match the active attempt.'});const now=Date.now(), expired=now>=Date.parse(attempt.expiresAt);const qs=db.questions.filter(q=>attempt.questionIds.includes(q.id)&&q.role===role);const expected=new Set(qs.map(q=>String(q.id))),ids=Object.keys(answers);if(!expired&&(ids.length!==qs.length||ids.some(x=>!expected.has(x))))return json(res,400,{error:`Please answer all ${qs.length} questions before submitting.`});if(ids.some(x=>!expected.has(x)))return json(res,400,{error:'Some assessment questions are invalid.'});if(ids.some(x=>!Number.isInteger(Number(answers[x]))||Number(answers[x])<0||Number(answers[x])>=qs.find(q=>String(q.id)===x).options.length))return json(res,400,{error:'One or more selected answers are invalid.'});let score=0;const per={};for(const q of qs){const good=Object.prototype.hasOwnProperty.call(answers,String(q.id))&&Number(answers[q.id])===q.correctIndex;score+=good?1:0;per[q.skillId]??={correct:0,total:0};per[q.skillId].total++;if(good)per[q.skillId].correct++;}attempt.status='submitted';attempt.submittedAt=new Date().toISOString();attempt.timedOut=expired;const result={id:id('assessment'),studentId:u.id,role,score,total:qs.length,assessedAt:new Date().toISOString(),attemptId:attempt.id,timedOut:expired};db.assessments.push(result);const skillMap=db.studentSkills[String(u.id)]??{};const details=[];for(const [sid,v] of Object.entries(per)){const level=Math.max(1,Math.min(5,Math.round(v.correct/v.total*5)));skillMap[sid]=level;details.push({skillId:Number(sid),correct:v.correct,total:v.total,level});}db.studentSkills[String(u.id)]=skillMap;db.resultSkills[String(result.id)]=details;save();const report=analyze(u.id,result.id);return json(res,200,{resultId:result.id,role,score,total:qs.length,percentage:Math.round(score/qs.length*100),timedOut:expired,report});}

    if(p==='/api/ai/report'&&method==='GET'){u=requireAuth(req,res,['student']);if(!u)return;return json(res,200,db.aiReports[String(u.id)]||null);}
    if(p==='/api/ai/analyze'&&method==='POST'){u=requireAuth(req,res,['student']);if(!u)return;const b=await readBody(req),report=analyze(u.id,Number(b.resultId));if(!report)return json(res,404,{error:'Assessment result not found.'});return json(res,200,report);}

    if(p==='/api/matching/internships'&&method==='GET'){u=requireAuth(req,res,['student']);if(!u)return;return json(res,200,matchInternships(u.id));}
    const cand=p.match(/^\/api\/matching\/candidates\/(\d+)$/);if(cand&&method==='GET'){u=requireAuth(req,res,['company']);if(!u)return;const i=db.internships.find(x=>x.id===Number(cand[1])&&x.companyId===u.id);if(!i)return json(res,404,{error:'Internship not found.'});const reqs=i.skills||[];const out=db.users.filter(x=>x.role==='student').map(st=>{const have=db.studentSkills[String(st.id)]||{};let ok=0;for(const z of reqs)if((have[String(z.skillId)]||0)>=z.requiredLevel)ok++;const sp=db.studentProfiles[String(st.id)]||{};return {id:st.id,name:st.name,email:st.email,college:sp.college||'',branch:sp.branch||'',careerGoal:sp.careerGoal||'',matchScore:reqs.length?Math.round(ok/reqs.length*100):0};}).sort((a,b)=>b.matchScore-a.matchScore);return json(res,200,out);}

    if(p==='/api/internships'&&method==='GET')return json(res,200,db.internships.filter(x=>x.status==='open').map(internshipView));
    if(p==='/api/internships'&&method==='POST'){u=requireAuth(req,res,['company']);if(!u)return;const b=await readBody(req);if(!b.title||!b.description||!b.location||!b.mode||!b.duration)return json(res,400,{error:'Complete the internship details.'});const x={id:id('internship'),companyId:u.id,title:b.title,description:b.description,location:b.location,mode:b.mode,duration:b.duration,openings:Number(b.openings)||1,status:'open',createdAt:new Date().toISOString(),skills:(b.skills||[]).map(v=>({skillId:Number(v.skillId),requiredLevel:Math.max(1,Math.min(5,Number(v.requiredLevel)||3))}))};db.internships.unshift(x);save();return json(res,201,{id:x.id,skills:internshipView(x).skills});}
    const appPost=p.match(/^\/api\/internships\/(\d+)\/apply$/);if(appPost&&method==='POST'){u=requireAuth(req,res,['student']);if(!u)return;const iid=Number(appPost[1]);const internship=db.internships.find(x=>x.id===iid&&x.status==='open');if(!internship)return json(res,404,{error:'Internship not found.'});if(db.applications.some(a=>a.internshipId===iid&&a.studentId===u.id))return json(res,409,{error:'You have already applied to this internship.'});const activeApplications=db.applications.filter(a=>a.internshipId===iid&&a.status!=='rejected').length;if(activeApplications>=Math.max(1,Number(internship.openings)||1))return json(res,409,{error:'This internship has reached its application capacity.'});const a={id:id('application'),internshipId:iid,studentId:u.id,status:'applied',appliedAt:new Date().toISOString()};db.applications.push(a);save();return json(res,201,{id:a.id,message:'Application submitted.'});}
    if(p==='/api/internships/applications/mine'&&method==='GET'){u=requireAuth(req,res,['student']);if(!u)return;const out=db.applications.filter(a=>a.studentId===u.id).sort((a,b)=>b.id-a.id).map(a=>{const i=db.internships.find(x=>x.id===a.internshipId),c=db.users.find(x=>x.id===i?.companyId);return {...a,internshipId:i?.id,title:i?.title,location:i?.location,mode:i?.mode,companyName:c?.name||''};});return json(res,200,out);}
    if(p==='/api/internships/company/applications'&&method==='GET'){u=requireAuth(req,res,['company']);if(!u)return;const out=db.applications.filter(a=>{const i=db.internships.find(x=>x.id===a.internshipId);return i?.companyId===u.id}).sort((a,b)=>b.id-a.id).map(a=>{const i=db.internships.find(x=>x.id===a.internshipId),s=db.users.find(x=>x.id===a.studentId),sp=db.studentProfiles[String(a.studentId)]||{};return {...a,studentId:s?.id,name:s?.name,email:s?.email,college:sp.college||'',branch:sp.branch||'',careerGoal:sp.careerGoal||'',internshipId:i?.id,title:i?.title};});return json(res,200,out);}
    const appPatch=p.match(/^\/api\/internships\/applications\/(\d+)$/);if(appPatch&&method==='PATCH'){u=requireAuth(req,res,['company']);if(!u)return;const b=await readBody(req),allowed=['shortlisted','interview','selected','rejected'];if(!allowed.includes(b.status))return json(res,400,{error:'Invalid status.'});const a=db.applications.find(x=>x.id===Number(appPatch[1]));const i=a&&db.internships.find(x=>x.id===a.internshipId);if(!a||!i||i.companyId!==u.id)return json(res,404,{error:'Application not found.'});a.status=b.status;save();return json(res,200,{message:'Application updated.'});}

    if(p==='/api/companies/me'&&method==='GET'){u=requireAuth(req,res,['company']);if(!u)return;const cp=db.companyProfiles[String(u.id)]||{};const ints=db.internships.filter(x=>x.companyId===u.id).map(i=>({...i,applications:db.applications.filter(a=>a.internshipId===i.id).length}));return json(res,200,{profile:{id:u.id,name:u.name,email:u.email,...cp},internships:ints});}
    if(p==='/api/companies/me'&&method==='PUT'){u=requireAuth(req,res,['company']);if(!u)return;const b=await readBody(req),x=db.users.find(v=>v.id===u.id);x.name=b.name||x.name;db.companyProfiles[String(u.id)]={industry:b.industry||'',website:b.website||'',location:b.location||'',description:b.description||''};save();return json(res,200,{message:'Company profile updated.'});}
    if(p==='/api/admin/overview'&&method==='GET'){u=requireAuth(req,res,['admin']);if(!u)return;return json(res,200,{students:db.users.filter(x=>x.role==='student').length,companies:db.users.filter(x=>x.role==='company').length,internships:db.internships.length,applications:db.applications.length});}
    return notFound(res);
  } catch(e) { console.error(e); return json(res,e.statusCode||500,{error:e.statusCode===400?'Invalid JSON request body.':'Server error. Please try again.'}); }
}

const MIME={'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.svg':'image/svg+xml','.ico':'image/x-icon'};
function serveStatic(req,res){
  let pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname);
  if(pathname==='/') pathname='/index.html';
  const file=path.normalize(path.join(FRONTEND,pathname));
  if(!file.startsWith(FRONTEND)) return res.writeHead(403).end('Forbidden');
  fs.readFile(file,(err,data)=>{
    if(!err){
      res.writeHead(200,{'Content-Type':MIME[path.extname(file)]||'application/octet-stream'});
      return res.end(data);
    }
    if(path.extname(file)===''){
      return fs.readFile(path.join(FRONTEND,'index.html'),(e,d)=>{
        if(e) return res.writeHead(404).end('Not found');
        res.writeHead(200,{'Content-Type':MIME['.html']});
        res.end(d);
      });
    }
    res.writeHead(404).end('Not found');
  });
}

const server=http.createServer(async(req,res)=>{if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':`http://${req.headers.host||'localhost:3000'}`,'Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Methods':'GET,POST,PUT,PATCH,OPTIONS','Vary':'Origin'});return res.end();}if(req.url.startsWith('/api/'))return handleApi(req,res);serveStatic(req,res);});
server.listen(PORT,()=>console.log(`SkillBridge running at http://localhost:${PORT}`));
