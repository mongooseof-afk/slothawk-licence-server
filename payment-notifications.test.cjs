const {test}=require('node:test'),assert=require('node:assert/strict');
const {PGlite}=require('@electric-sql/pglite');
const {normalize,paymentUrl,formatPayment,createPaymentNotifications}=require('./payment-notifications');
const data={token:'valid',eventId:'a'.repeat(64),mission:'aut',city:'ASRB',subcategory:'Tourism',durationMs:10123,paymentUrl:'https://visa.vfsglobal.com/PG-Component/Payment/CMI?initiateResult=test-only'};
test('validates payment data and formats the private admin message without HTML interpretation',()=>{
 assert.ok(normalize(data));
 for(const patch of [{durationMs:NaN},{durationMs:-1},{mission:'nld'},{city:'MLMRBT'},{subcategory:'a\nb'},{paymentUrl:'https://evil.test/pay'},{paymentUrl:'https://visa.vfsglobal.com.evil.test/PG-Component/Payment/CMI'},{eventId:'bad'}])assert.equal(normalize({...data,...patch}),null);
 assert.equal(paymentUrl('http://visa.vfsglobal.com/PG-Component/Payment/CMI'),false);
 assert.equal(paymentUrl('https://u:p@visa.vfsglobal.com/PG-Component/Payment/CMI'),false);
 assert.equal(formatPayment(data,'Admin <name>'),'✅ [Austria][Rabat][Tourism]\n\nUSER : Admin <name>\n\nTOTAL TIME BOOKING : 10.1s\n\nPAYMENT LINK :\n'+data.paymentUrl);
});
test('database-backed authentication, concurrent deduplication, private delivery and restart recovery',async()=>{
 const db=new PGlite();
 try{
 await db.exec(`CREATE TABLE licences(license_key TEXT,username TEXT,status TEXT,expires_at TIMESTAMPTZ,deactivated BOOLEAN,blocked BOOLEAN,machine_id TEXT,known_devices JSONB,max_devices INTEGER);
 INSERT INTO licences VALUES('owner','Real licence name','active',NULL,FALSE,FALSE,'machine','[]',1);`);
 const sent=[];let responseMode='ok';
 const options={pool:db,token:'secret-fixture-token',chatId:'-1001234567890',verifyToken:t=>{if(t!=='valid')throw Error('invalid');return {license_key:'owner',machine_id:'machine'};},isDeviceAllowed:(l,id)=>l.machine_id===id,
 send:async(url,req)=>{sent.push({url,body:JSON.parse(req.body)});if(responseMode==='network')throw Error('uncertain');return {ok:responseMode==='ok',status:responseMode==='rate'?429:responseMode==='fail'?403:200,json:async()=>responseMode==='ok'?{ok:true,result:{chat:{id:-1001234567890},message_id:123}}:responseMode==='rate'?{ok:false,error_code:429,parameters:{retry_after:2}}:{ok:false,error_code:403}};}};
 let service=createPaymentNotifications(options);await service.initialize();
 assert.equal((await service.accept({...data,token:'bad'})).status,401);
 await db.exec("UPDATE licences SET blocked=TRUE");assert.equal((await service.accept(data)).status,403);await db.exec("UPDATE licences SET blocked=FALSE");
 const receipts=await Promise.all([service.accept({...data,username:'Spoof',chatId:'other'}),service.accept(data)]);
 assert.ok(receipts.every(r=>r.ok));assert.equal((await db.query('SELECT * FROM payment_notifications')).rows.length,1);
 service=createPaymentNotifications(options);await service.initialize();await service.deliver();
 assert.equal(sent.length,1);assert.equal(sent[0].body.chat_id,'-1001234567890');assert.match(sent[0].body.text,/USER : Real licence name/);assert.equal(sent[0].body.link_preview_options.is_disabled,true);assert.equal(sent[0].body.parse_mode,undefined);
 assert.equal((await db.query('SELECT body FROM payment_notifications')).rows[0].body,null);
 await service.accept(data);await service.deliver();assert.equal(sent.length,1);
 responseMode='rate';await service.accept({...data,eventId:'b'.repeat(64)});await service.deliver();
 assert.equal((await db.query("SELECT state FROM payment_notifications WHERE state='queued'")).rows.length,1);
 responseMode='ok';await db.exec("UPDATE payment_notifications SET due=NOW() WHERE state='queued'");await service.deliver();
 responseMode='network';await service.accept({...data,eventId:'c'.repeat(64)});await service.deliver();const count=sent.length;await service.deliver();assert.equal(sent.length,count);
 assert.equal((await db.query("SELECT body FROM payment_notifications WHERE state='unconfirmed'")).rows[0].body,null);
 responseMode='fail';await service.accept({...data,eventId:'d'.repeat(64)});await service.deliver();assert.equal((await db.query("SELECT body FROM payment_notifications WHERE state='failed'")).rows[0].body,null);
 await service.accept({...data,eventId:'e'.repeat(64)});await db.exec("UPDATE payment_notifications SET state='sending',due=NOW()-INTERVAL '3 minutes' WHERE state='queued'");await service.deliver();
 assert.equal((await db.query("SELECT state FROM payment_notifications WHERE state='sending'")).rows.length,0);
 await service.accept({...data,eventId:'f'.repeat(64)});await db.exec("UPDATE payment_notifications SET created_at=NOW()-INTERVAL '25 hours' WHERE state='queued'");await service.deliver();assert.equal((await db.query("SELECT body FROM payment_notifications WHERE state='expired'")).rows[0].body,null);
 }finally{await db.close();}
});
