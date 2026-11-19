const { createHash } = require('node:crypto');

const COUNTRIES = {mlt:'Malta',aut:'Austria',fin:'Finland',swe:'Sweden',hrv:'Croatia'};
const CITIES = {MLMCS:'Casablanca',MLMRBT:'Rabat',MLMTGR:'Tangier',ASCA:'Casablanca',ASRB:'Rabat',TVC:'Tangier',Rbt:'Rabat',SWRA:'Rabat',CVARC:'Rabat'};
const CENTRES = {mlt:['MLMCS','MLMRBT','MLMTGR'],aut:['ASCA','ASRB','TVC'],fin:['Rbt'],swe:['SWRA'],hrv:['CVARC']};
function paymentUrl(value) {
  if(typeof value!=='string'||value.length>3000||/[\s\x00-\x1f]/.test(value))return false;
  try {const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password&&!u.port&&
    ((['visa.vfsglobal.com','lift-api.vfsglobal.com','online.vfsglobal.com'].includes(u.hostname)&&/^\/PG-Component\/Payment\/(CMI|PayRequest)$/i.test(u.pathname))||
    (u.hostname==='payment.cmi.co.ma'&&u.pathname==='/fim/est3Dgate'));}catch{return false;}
}
function normalize(raw) {
  if(!raw||typeof raw!=='object'||!COUNTRIES[raw.mission]||!CENTRES[raw.mission].includes(raw.city)||
    typeof raw.subcategory!=='string'||!raw.subcategory.trim()||raw.subcategory.length>120||/[\x00-\x1f]/.test(raw.subcategory)||
    !paymentUrl(raw.paymentUrl)||!Number.isFinite(raw.durationMs)||raw.durationMs<0||raw.durationMs>86400000||
    typeof raw.eventId!=='string'||!/^[a-f0-9]{64}$/.test(raw.eventId))return null;
  return {eventId:raw.eventId,mission:raw.mission,city:raw.city,subcategory:raw.subcategory.trim(),paymentUrl:raw.paymentUrl,durationMs:Math.round(raw.durationMs)};
}
function formatPayment(n, username) {
  // Plain text: no HTML interpretation or link previews of sensitive payment URLs.
  const name=String(username||'Unnamed user').replace(/[\x00-\x1f]/g,' ').slice(0,120);
  return `✅ [${COUNTRIES[n.mission]}][${CITIES[n.city]}][${n.subcategory}]\n\nUSER : ${name}\n\nTOTAL TIME BOOKING : ${(n.durationMs/1000).toFixed(1)}s\n\nPAYMENT LINK :\n${n.paymentUrl}`;
}
function createPaymentNotifications({pool,verifyToken,isDeviceAllowed,token,chatId,send=fetch}) {
  const configured=()=>!!token&&/^-100\d+$/.test(chatId);
  let busy=false;
  async function init(){await pool.query(`CREATE TABLE IF NOT EXISTS payment_notifications (
    id TEXT PRIMARY KEY, owner TEXT NOT NULL, body TEXT, state TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
    due TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), message_id BIGINT
  )`);}
  async function accept(raw){
    if(!configured())return {status:503,reason:'payment_notifications_unavailable'};
    let decoded;try{decoded=verifyToken(raw?.token);}catch{return {status:401,reason:'invalid_token'};}
    if(!decoded?.license_key||!decoded.machine_id)return {status:401,reason:'invalid_token'};
    const n=normalize(raw);
    if(!n)return {status:400,reason:'invalid_payment_notification'};
    const {rows}=await pool.query('SELECT username,status,expires_at,deactivated,blocked,machine_id,known_devices,max_devices FROM licences WHERE license_key=$1',[decoded.license_key]);
    const l=rows[0];
    if(!l||l.status!=='active'||l.blocked||l.deactivated||(l.expires_at&&Date.now()>=new Date(l.expires_at).getTime())||!isDeviceAllowed(l,decoded.machine_id))return {status:403,reason:'licence_inactive'};
    const id=createHash('sha256').update(decoded.license_key+'\0'+n.eventId).digest('hex');
    const existing=await pool.query('SELECT state FROM payment_notifications WHERE id=$1',[id]);
    if(existing.rows.length)return {status:200,ok:true};
    const owner=createHash('sha256').update(decoded.license_key).digest('hex');
    const quota=await pool.query("SELECT COUNT(*)::int AS count FROM payment_notifications WHERE created_at>NOW()-INTERVAL '1 minute' AND owner=$1",[owner]);
    if(quota.rows[0]?.count>=20)return {status:429,reason:'rate_limited'};
    await pool.query('INSERT INTO payment_notifications(id,owner,body) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING',[id,owner,formatPayment(n,l.username)]);
    return {status:202,ok:true};
  }
  async function deliver(){
    if(busy||!configured())return;
    busy=true;
    try{
      // A process can disappear after Telegram accepts a send. Do not resend uncertain deliveries.
      await pool.query("UPDATE payment_notifications SET state='unconfirmed',body=NULL WHERE state='sending' AND due<NOW()-INTERVAL '2 minutes'");
      await pool.query("UPDATE payment_notifications SET state='expired',body=NULL WHERE body IS NOT NULL AND created_at<NOW()-INTERVAL '24 hours'");
      const {rows}=await pool.query(`UPDATE payment_notifications SET state='sending',attempts=attempts+1,due=NOW()
        WHERE id=(SELECT id FROM payment_notifications WHERE state='queued' AND due<=NOW() ORDER BY due LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *`);
      const job=rows[0];if(!job)return;
      let state='unconfirmed',messageId=null,retryAfter=null;
      try{
        const response=await send('https://api.telegram.org/bot'+token+'/sendMessage',{method:'POST',redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:chatId,text:job.body,link_preview_options:{is_disabled:true},protect_content:true})});
        const result=await response.json();
        if(response.ok&&result.ok===true&&String(result.result?.chat?.id)===chatId&&Number.isSafeInteger(result.result?.message_id)){
          state='sent';messageId=result.result.message_id;
        }else if(response.status===429&&result.error_code===429&&job.attempts<5){
          state='queued';retryAfter=Math.min(3600,Math.max(1,Number(result.parameters?.retry_after)||60));
        }else if(response.status>=400&&response.status<500&&result.ok===false)state='failed';
      }catch{/* Never log bot tokens, payment links or Telegram response bodies. */}
      await pool.query("UPDATE payment_notifications SET state=$2,body=CASE WHEN $2='queued' THEN body ELSE NULL END,message_id=$3,due=NOW()+($4::int*INTERVAL '1 second') WHERE id=$1",[job.id,state,messageId,retryAfter||0]);
      if(state==='failed'||state==='unconfirmed')console.warn('[PAYMENT] Delivery '+state);
    }finally{busy=false;}
  }
  return {initialize:init,accept,deliver};
}
module.exports={normalize,paymentUrl,formatPayment,createPaymentNotifications};
