
const sorts = {createdAt:'created_at',created_at:'created_at',activatedAt:'activated_at',expiresAt:'expires_at',lastSeen:'last_seen',status:'status'};
const statusSql = "CASE WHEN status NOT IN ('revoked','deactivated') AND expires_at <= NOW() THEN 'expired' ELSE status END";
async function listLicenceRows(pool, rawUrl) {
  const q=new URL(rawUrl,'http://localhost').searchParams;
  const integer=(name,fallback,max)=>{
    const n=Number(q.get(name)||fallback);
    if(!Number.isInteger(n)||n<1||n>max)throw Error('Invalid '+name);
    return n;
  };
  const page=integer('page',1,1000000),limit=integer('limit',25,1000);
  const values=[],clauses=[];
  const search=(q.get('search')||'').trim().slice(0,120);
  const status=q.get('status')||'all';
  if(search){ values.push('%'+search+'%');clauses.push("(username ILIKE $1 OR license_key ILIKE $1 OR COALESCE(machine_id,'') ILIKE $1 OR COALESCE(last_ip,'') ILIKE $1)"); }
  if(status!=='all'){
    if(!['active','pending','revoked','expired','deactivated'].includes(status))throw Error('Invalid status');
    values.push(status);clauses.push('('+statusSql+') = $'+values.length);
  }
  const where=clauses.length?' WHERE '+clauses.join(' AND '):'';
  const count=await pool.query('SELECT COUNT(*) AS total FROM licences'+where,values);
  const total=Number(count.rows[0].total);
  const column=sorts[q.get('sortBy')]||'created_at';
  const direction=q.get('sortOrder')==='asc'?'ASC':'DESC';
  const data=await pool.query('SELECT * FROM licences'+where+' ORDER BY '+column+' '+direction+', id ASC LIMIT $'+(values.length+1)+' OFFSET $'+(values.length+2),[...values,limit,(page-1)*limit]);
  return {rows:data.rows,total,page,limit,totalPages:Math.max(1,Math.ceil(total/limit))};
}
module.exports={listLicenceRows};
