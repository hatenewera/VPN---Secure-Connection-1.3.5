import React,{useEffect,useMemo,useRef,useState}from'react';
import{createRoot}from'react-dom/client';
import{invoke}from'@tauri-apps/api/core';
import{getCurrentWindow}from'@tauri-apps/api/window';
import'./style.css';

const T={ru:{welcome:'Добро пожаловать в EGA VPN',welcome2:'Быстрое и аккуратное подключение без лишнего.',start:'Начать работу',home:'Подключение',servers:'Серверы',stats:'Статистика',logs:'Логи',settings:'Настройки',routing:'Маршрутизация',connect:'Подключиться',disconnect:'Отключиться',add:'Добавить ключ',subscription:'Импорт подписки',subscriptionHint:'Вставьте URL подписки — EGA VPN загрузит и добавит найденные серверы.',importSub:'Импортировать',imported:'Импортировано серверов',empty:'Серверов пока нет',empty2:'Добавьте свой VPN-ключ — он появится здесь.',ping:'Пинг',connected:'Подключено',off:'Отключено',time:'Время подключения',down:'Скорость загрузки',up:'Скорость выгрузки',received:'Получено',sent:'Отправлено',total:'Всего',autostart:'Запускать вместе с Windows',autoconnect:'Подключаться автоматически',language:'Язык',key:'VPN-ключ',name:'Название сервера',cancel:'Отмена',addServer:'Добавить сервер',clear:'Очистить',noLogs:'Логов пока нет',remove:'Удалить',status:'Статус',online:'Доступен',failed:'Ошибка',saved:'Сервер сохранён',globalRoute:'Весь трафик через VPN',selectedRoute:'Только выбранные сайты',rulesRoute:'Правила',routeDefault:'Остальное',proxy:'VPN',direct:'DIRECT',block:'BLOCK',addRule:'Добавить правило',ruleTarget:'Домен, IP или CIDR',apply:'Применить'},en:{welcome:'Welcome to EGA VPN',welcome2:'Fast, clean and focused connectivity.',start:'Get started',home:'Connection',servers:'Servers',stats:'Statistics',logs:'Logs',settings:'Settings',routing:'Routing',connect:'Connect',disconnect:'Disconnect',add:'Add key',subscription:'Import subscription',subscriptionHint:'Paste a subscription URL — EGA VPN will download and add the found servers.',importSub:'Import',imported:'Servers imported',empty:'No servers yet',empty2:'Add your VPN key — it will appear here.',ping:'Ping',connected:'Connected',off:'Disconnected',time:'Connection time',down:'Download speed',up:'Upload speed',received:'Received',sent:'Sent',total:'Total',autostart:'Launch with Windows',autoconnect:'Auto-connect',language:'Language',key:'VPN key',name:'Server name',cancel:'Cancel',addServer:'Add server',clear:'Clear',noLogs:'No logs yet',remove:'Remove',status:'Status',online:'Available',failed:'Error',saved:'Server saved',globalRoute:'All traffic through VPN',selectedRoute:'Only selected sites',rulesRoute:'Rules',routeDefault:'Fallback',proxy:'VPN',direct:'DIRECT',block:'BLOCK',addRule:'Add rule',ruleTarget:'Domain, IP or CIDR',apply:'Apply'}};

const b64=s=>{try{return decodeURIComponent(escape(atob(s.replace(/-/g,'+').replace(/_/g,'/'))))}catch{return atob(s)}};
const q=(u,k,d='')=>u.searchParams.get(k)??d;
const num=(v,d)=>Number(v||d);
function decodeSubscription(text){
 const raw=text.trim();
 const candidates=[raw, raw.replace(/\s+/g,'')];
 for(const c of candidates){
   if(/(?:vless|vmess|trojan|ss|shadowsocks|hysteria2|hy2):\/\//i.test(c)) return c;
   try{
     const d=decodeURIComponent(escape(atob(c.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4-(c.length%4))%4))));
     if(/(?:vless|vmess|trojan|ss|shadowsocks|hysteria2|hy2):\/\//i.test(d)) return d;
   }catch{}
 }
 return '';
}
function subscriptionItems(text){
 const decoded=decodeSubscription(text);
 const source=decoded||text;
 return source.split(/\r?\n/).map(x=>x.trim()).filter(Boolean).filter(x=>/^(vless|vmess|trojan|ss|shadowsocks|hysteria2|hy2):\/\//i.test(x));
}


function buildConfig(raw, routing={mode:'global',rules:[]}){
 const text=raw.trim(); let u;
 try{u=new URL(text.replace(/^hy2:\/\//,'hysteria2://'))}catch{throw Error('Invalid VPN key')}
 const proto=u.protocol.replace(':','').toLowerCase();
 const common={log:{loglevel:'warning'},dns:{servers:['1.1.1.1','8.8.8.8']},inbounds:[{tag:'tun-in',protocol:'tun',settings:{name:'EGA-VPN',desc:'EGA VPN',mtu:1500,gateway:['10.66.0.1/30','fd66:66:66::1/126'],dns:['1.1.1.1','8.8.8.8'],autoSystemRoutingTable:['0.0.0.0/0','::/0'],autoOutboundsInterface:'auto'}}],outbounds:[],routing:{domainStrategy:'IPIfNonMatch',rules:[]}};
 let outbound={tag:'proxy'};
 if(proto==='vless'){
   outbound.protocol='vless'; outbound.settings={vnext:[{address:u.hostname,port:num(u.port,443),users:[{id:decodeURIComponent(u.username),encryption:'none',flow:q(u,'flow','')}]}]};
   const net=q(u,'type',q(u,'network','tcp')); const sec=q(u,'security','none'); const ss={network:net==='tcp'?'raw':net,security:sec};
   if(net==='ws')ss.wsSettings={path:q(u,'path','/'),headers:{Host:q(u,'host','')}};
   if(net==='grpc')ss.grpcSettings={serviceName:q(u,'serviceName',q(u,'path','')),multiMode:q(u,'mode','')==='multi'};
   if(net==='httpupgrade')ss.httpupgradeSettings={path:q(u,'path','/'),host:q(u,'host','')};
   if(net==='xhttp')ss.xhttpSettings={path:q(u,'path','/'),host:q(u,'host',''),mode:q(u,'mode','auto')};
   if(sec==='tls')ss.tlsSettings={serverName:q(u,'sni',u.hostname),fingerprint:q(u,'fp','chrome'),allowInsecure:q(u,'allowInsecure','0')==='1'};
   if(sec==='reality')ss.realitySettings={serverName:q(u,'sni',u.hostname),fingerprint:q(u,'fp','chrome'),publicKey:q(u,'pbk',''),shortId:q(u,'sid',''),spiderX:q(u,'spx','')};
   outbound.streamSettings=ss;
 } else if(proto==='vmess'){
   let data;try{data=JSON.parse(b64(text.slice(8)))}catch{throw Error('Invalid VMess key')}
   outbound.protocol='vmess';outbound.settings={vnext:[{address:data.add,port:num(data.port,443),users:[{id:data.id,alterId:num(data.aid,0),security:data.scy||'auto'}]}]};
   const net=data.net||'tcp';const sec=data.tls?'tls':'none';const ss={network:net==='tcp'?'raw':net,security:sec};
   if(net==='ws')ss.wsSettings={path:data.path||'/',headers:{Host:data.host||data.add}};
   if(net==='grpc')ss.grpcSettings={serviceName:data.path||data.serviceName||''};
   if(sec==='tls')ss.tlsSettings={serverName:data.sni||data.host||data.add,allowInsecure:false};
   outbound.streamSettings=ss;
 } else if(proto==='trojan'){
   outbound.protocol='trojan';outbound.settings={servers:[{address:u.hostname,port:num(u.port,443),password:decodeURIComponent(u.username)}]};
   const net=q(u,'type','tcp');const ss={network:net==='tcp'?'raw':net,security:q(u,'security','tls')};
   if(net==='ws')ss.wsSettings={path:q(u,'path','/'),headers:{Host:q(u,'host','')}};
   if(net==='grpc')ss.grpcSettings={serviceName:q(u,'serviceName',q(u,'path',''))};
   if(ss.security==='tls')ss.tlsSettings={serverName:q(u,'sni',u.hostname),allowInsecure:q(u,'allowInsecure','0')==='1'};
   outbound.streamSettings=ss;
 } else if(proto==='ss'||proto==='shadowsocks'){
   let userinfo=decodeURIComponent(u.username);let method,password;
   if(userinfo.includes(':'))[method,password]=userinfo.split(/:(.*)/s);else{let dec=b64(u.hostname+u.pathname);[method,password]=dec.split(/:(.*)/s)}
   if(!method||!password)throw Error('Invalid Shadowsocks key');
   outbound.protocol='shadowsocks';outbound.settings={servers:[{address:u.hostname,port:num(u.port,443),method,password} ]};
 } else if(proto==='hysteria2'||proto==='hy2'){
   outbound.protocol='hysteria';outbound.settings={version:2,address:u.hostname,port:num(u.port,443)};
   const ss={network:'hysteria',security:'tls',hysteriaSettings:{version:2,auth:decodeURIComponent(u.username||q(u,'auth',''))}};
   if(q(u,'sni',''))ss.tlsSettings={serverName:q(u,'sni',u.hostname),allowInsecure:q(u,'insecure','0')==='1'};
   if(q(u,'pinSHA256',''))ss.tlsSettings={...(ss.tlsSettings||{serverName:u.hostname}),certificates:[{usage:'verify',certificateFile:q(u,'pinSHA256')}]};
   outbound.streamSettings=ss;
 } else throw Error('Unsupported protocol: '+proto);
 common.outbounds=[outbound,{protocol:'freedom',tag:'direct'},{protocol:'blackhole',tag:'block'}];
 const rr=[];
 if(routing.mode==='selected'){
   for(const r of (routing.rules||[])){ if(!r.value) continue; rr.push({type:'field',domain:r.kind==='domain'?[r.value]:undefined,ip:r.kind==='ip'?[r.value]:undefined,outboundTag:r.action}); }
   rr.push({type:'field',network:'tcp,udp',outboundTag:'direct'});
 } else {
   for(const r of (routing.rules||[])){ if(!r.value) continue; rr.push({type:'field',domain:r.kind==='domain'?[r.value]:undefined,ip:r.kind==='ip'?[r.value]:undefined,outboundTag:r.action}); }
 }
 common.routing.rules=rr.map(r=>{if(!r.domain)delete r.domain;if(!r.ip)delete r.ip;return r;});
 return common;
}

const fmtBytes=n=>n>=1e9?(n/1e9).toFixed(2)+' GB':n>=1e6?(n/1e6).toFixed(2)+' MB':n>=1e3?(n/1e3).toFixed(1)+' KB':'0 KB';
const fmtRate=n=>n>=1e6?(n/1e6).toFixed(2)+' MB/s':n>=1e3?(n/1e3).toFixed(1)+' KB/s':'0 KB/s';
const fmtTime=s=>`${String(Math.floor(s/3600)).padStart(2,'0')}:${String(Math.floor(s/60)%60).padStart(2,'0')}:${String(s%60).padStart(2,'0')}`;

function App(){
 const appWindow=getCurrentWindow();
 const startWindowDrag=async(e)=>{ if(e.button===0){ try{await appWindow.startDragging()}catch{} } };
 const[Lg,setLg]=useState(localStorage.getItem('lang')||'ru');const L=T[Lg];
 const[first,setFirst]=useState(localStorage.getItem('ega-welcome')!=='1');const[page,setPage]=useState('home');const[routeMode,setRouteMode]=useState(localStorage.getItem('ega-route-mode')||'global');const[routeRules,setRouteRules]=useState(()=>JSON.parse(localStorage.getItem('ega-route-rules')||'[]'));const[routeValue,setRouteValue]=useState('');const[routeKind,setRouteKind]=useState('domain');const[routeAction,setRouteAction]=useState('proxy');
 const[servers,setServers]=useState(()=>JSON.parse(localStorage.getItem('ega-servers')||'[]'));const[sel,setSel]=useState(0);const[conn,setConn]=useState(false);const[started,setStarted]=useState(0);
 const[traffic,setTraffic]=useState({rx:0,tx:0,rr:0,tr:0});const[logs,setLogs]=useState(()=>JSON.parse(localStorage.getItem('ega-logs')||'[]'));const[modal,setModal]=useState(false);const[mode,setMode]=useState('key');const[key,setKey]=useState('');const[name,setName]=useState('');const[subUrl,setSubUrl]=useState('');const[auto,setAuto]=useState(localStorage.getItem('autostart')==='1');const[ac,setAc]=useState(localStorage.getItem('autoconnect')==='1');const[err,setErr]=useState('');
 const s=servers[sel];const prev=useRef({rx:0,tx:0,t:Date.now()});
 useEffect(()=>localStorage.setItem('ega-servers',JSON.stringify(servers)),[servers]);useEffect(()=>localStorage.setItem('ega-logs',JSON.stringify(logs.slice(-500))),[logs]);useEffect(()=>localStorage.setItem('lang',Lg),[Lg]);useEffect(()=>localStorage.setItem('ega-route-mode',routeMode),[routeMode]);useEffect(()=>localStorage.setItem('ega-route-rules',JSON.stringify(routeRules)),[routeRules]);
 const log=(level,msg)=>setLogs(x=>[...x,{time:new Date().toLocaleTimeString(),level,msg}]);
 useEffect(()=>{if(!conn)return;let id=setInterval(async()=>{try{const st=await invoke('xray_stats');const now=Date.now(),dt=Math.max(0.1,(now-prev.current.t)/1000);const rr=Math.max(0,(st.received||0)-prev.current.rx)/dt;const tr=Math.max(0,(st.sent||0)-prev.current.tx)/dt;setTraffic({rx:st.received||0,tx:st.sent||0,rr,tr});prev.current={rx:st.received||0,tx:st.sent||0,t:now}}catch{}},1000);return()=>clearInterval(id)},[conn]);
 useEffect(()=>{if(!conn)return;const id=setInterval(()=>{},1000);return()=>clearInterval(id)},[conn]);
 const duration=started?Math.floor((Date.now()-started)/1000):0;
 async function connect(){if(!s)return;setErr('');try{const cfg=buildConfig(s.raw,{mode:routeMode,rules:routeRules});await invoke('xray_start',{config:JSON.stringify(cfg)});setConn(true);setStarted(Date.now());prev.current={rx:0,tx:0,t:Date.now()};log('INFO','Connected: '+s.name)}catch(e){const m=String(e);setErr(m);log('ERROR',m)}}
 async function disconnect(){try{await invoke('xray_stop')}catch(e){log('ERROR',String(e))}setConn(false);setStarted(0);log('INFO','Disconnected')}
 async function ping(i=sel){const x=servers[i];if(!x)return;try{const ms=await invoke('xray_ping',{host:x.host,port:x.port||443});setServers(a=>a.map((v,j)=>j===i?{...v,ping:ms}:v));log('INFO',`Ping ${x.host}: ${ms} ms`)}catch(e){log('ERROR','Ping failed: '+e)}}
 function add(){try{buildConfig(key);const u=new URL(key.trim().replace(/^hy2:\/\//,'hysteria2://'));const proto=u.protocol.replace(':','');const item={name:name||u.hostname,protocol:proto==='hy2'?'Hysteria 2':proto==='ss'?'Shadowsocks':proto[0].toUpperCase()+proto.slice(1),host:u.hostname,port:Number(u.port||443),raw:key.trim(),ping:null};setServers(a=>[...a,item]);setSel(servers.length);setModal(false);setKey('');setName('');log('INFO','Server added: '+item.name);setErr('')}catch(e){setErr(String(e));log('ERROR',String(e))}}
 async function importSubscription(){
   try{
     const url=subUrl.trim();
     if(!/^https?:\/\//i.test(url))throw Error('Invalid subscription URL');
     const text=await invoke('fetch_subscription',{url});
     const keys=subscriptionItems(text);
     if(!keys.length)throw Error('No supported VPN keys found in subscription');
     const items=[];
     for(const raw of keys){
       try{
         const u=new URL(raw.replace(/^hy2:\/\//,'hysteria2://')); const proto=u.protocol.replace(':','').toLowerCase();
         buildConfig(raw);
         items.push({name:u.hostname,protocol:proto==='hy2'?'Hysteria 2':proto==='ss'?'Shadowsocks':proto[0].toUpperCase()+proto.slice(1),host:u.hostname,port:Number(u.port||443),raw,ping:null});
       }catch{}
     }
     if(!items.length)throw Error('Subscription contained no valid supported servers');
     setServers(a=>[...a,...items]);setSel(servers.length);setModal(false);setSubUrl('');log('INFO',`${L.imported}: ${items.length}`);setErr('');
   }catch(e){setErr(String(e));log('ERROR',String(e))}
 }
 function addRule(){const v=routeValue.trim();if(!v)return;setRouteRules(a=>[...a,{value:v,kind:routeKind,action:routeAction}]);setRouteValue('')}
 function removeRule(i){setRouteRules(a=>a.filter((_,j)=>j!==i))}
 function remove(i){if(conn&&i===sel)disconnect();setServers(a=>a.filter((_,j)=>j!==i));setSel(0);log('INFO','Server removed')}
 if(first)return <div className="welcome"><div className="window-drag" data-tauri-drag-region onMouseDown={startWindowDrag}><span>EGA VPN</span><span className="window-drag-hint">EGA MINIMAL</span></div><div className="glass"><div className="logo">E</div><div className="eyebrow">EGA MINIMAL</div><h1>{L.welcome}</h1><p>{L.welcome2}</p><button className="primary big" onClick={()=>{localStorage.setItem('ega-welcome','1');setFirst(false)}}>{L.start}<span>→</span></button><div className="welcomeLang"><button onClick={()=>setLg('ru')} className={Lg==='ru'?'selected':''}>RU</button><button onClick={()=>setLg('en')} className={Lg==='en'?'selected':''}>EN</button></div></div></div>;
 return <div className="app"><div className="window-drag" data-tauri-drag-region onMouseDown={startWindowDrag}><span>EGA VPN</span><span className="window-drag-hint">EGA MINIMAL</span></div><aside><div className="brand"><i/>EGA VPN</div>{[['home','⌂'],['servers','◉'],['routing','⇄'],['stats','◌'],['logs','≡'],['settings','⚙']].map(([k,ic])=><button key={k} className={'nav '+(page===k?'active':'')} onClick={()=>setPage(k)}><b>{ic}</b>{L[k]}</button>)}<div className="bottom"><select value={Lg} onChange={e=>setLg(e.target.value)}><option value="ru">Русский</option><option value="en">English</option></select></div></aside><main><header><div><small>EGA MINIMAL</small><h1>{L[page]}</h1></div><div className={'status '+(conn?'on':'')}><i/>{conn?L.connected:L.off}</div></header>
 {err&&<div className="errorbar">{err}</div>}
 {page==='home'&&<div className="home"><div className={'orb '+(conn?'live':'')}><span>{conn?'ON':'OFF'}</span></div><div className="current">{s?<><strong>{s.name}</strong><em>{s.protocol} · {s.host}</em></>:<><strong>{L.empty}</strong><em>{L.empty2}</em></>}</div><div className="actions">{s&&(conn?<button className="primary" onClick={disconnect}>{L.disconnect}</button>:<button className="primary" onClick={connect}>{L.connect}</button>)}<button className="secondary" onClick={()=>setModal(true)}>＋ {L.add}</button></div></div>}
 {page==='servers'&&<div className="content">{servers.length?<div className="cards">{servers.map((x,i)=><article key={x.raw+i} className={'card '+(i===sel?'selected':'')} onClick={()=>setSel(i)}><div><h3>{x.name}</h3><p>{x.protocol} · {x.host}</p></div><span>{x.ping==null?'—':x.ping+' ms'}</span><div className="row"><button onClick={e=>{e.stopPropagation();ping(i)}}>{L.ping}</button><button onClick={e=>{e.stopPropagation();setSel(i);i===sel&&conn?disconnect():connect()}}>{conn&&i===sel?L.disconnect:L.connect}</button><button onClick={e=>{e.stopPropagation();remove(i)}}>{L.remove}</button></div></article>)}<button className="addCard" onClick={()=>setModal(true)}>＋ {L.add}</button></div>:<div className="empty"><div>＋</div><h2>{L.empty}</h2><p>{L.empty2}</p><button className="primary" onClick={()=>setModal(true)}>{L.add}</button></div>}</div>}
 {page==='routing'&&<div className="content routing"><div className="route-modes"><button className={routeMode==='global'?'routeMode active':'routeMode'} onClick={()=>setRouteMode('global')}>{L.globalRoute}</button><button className={routeMode==='selected'?'routeMode active':'routeMode'} onClick={()=>setRouteMode('selected')}>{L.selectedRoute}</button><button className={routeMode==='rules'?'routeMode active':'routeMode'} onClick={()=>setRouteMode('rules')}>{L.rulesRoute}</button></div><div className="route-panel"><h3>{L.routing}</h3><p className="hint">{routeMode==='global'?L.globalRoute:routeMode==='selected'?L.selectedRoute:L.rulesRoute}</p><div className="rule-add"><select value={routeKind} onChange={e=>setRouteKind(e.target.value)}><option value="domain">Domain</option><option value="ip">IP / CIDR</option></select><input value={routeValue} onChange={e=>setRouteValue(e.target.value)} placeholder={L.ruleTarget}/><select value={routeAction} onChange={e=>setRouteAction(e.target.value)}><option value="proxy">{L.proxy}</option><option value="direct">{L.direct}</option><option value="block">{L.block}</option></select><button className="primary" onClick={addRule}>＋ {L.addRule}</button></div><div className="rules-list">{routeRules.length?routeRules.map((r,i)=><div className="rule" key={i}><span>{r.value}</span><small>{r.kind}</small><b>{r.action==='proxy'?L.proxy:r.action==='direct'?L.direct:L.block}</b><button onClick={()=>removeRule(i)}>×</button></div>):<div className="noLogs">{L.empty}</div>}</div><button className="secondary" onClick={()=>log('INFO',L.apply)}>{L.apply}</button></div></div>}
  {page==='stats'&&<div className="content grid">{[[L.time,fmtTime(duration)],[L.down,fmtRate(traffic.rr)],[L.up,fmtRate(traffic.tr)],[L.received,fmtBytes(traffic.rx)],[L.sent,fmtBytes(traffic.tx)],[L.total,fmtBytes(traffic.rx+traffic.tx)]].map(([a,b])=><div className="metric" key={a}><small>{a}</small><strong>{b}</strong></div>)}</div>}
 {page==='logs'&&<div className="content"><div className="logbox">{logs.length?logs.map((x,i)=><div className="line" key={i}><time>{x.time}</time><b className={x.level.toLowerCase()}>{x.level}</b><span>{x.msg}</span></div>):<div className="noLogs">{L.noLogs}</div>}</div><button className="secondary" onClick={()=>setLogs([])}>{L.clear}</button></div>}
 {page==='settings'&&<div className="content settings"><label>{L.autostart}<input type="checkbox" checked={auto} onChange={e=>{setAuto(e.target.checked);localStorage.setItem('autostart',e.target.checked?'1':'0')}}/></label><label>{L.autoconnect}<input type="checkbox" checked={ac} onChange={e=>{setAc(e.target.checked);localStorage.setItem('autoconnect',e.target.checked?'1':'0')}}/></label><label>{L.language}<select value={Lg} onChange={e=>setLg(e.target.value)}><option value="ru">Русский</option><option value="en">English</option></select></label></div>}
 {modal&&<div className="overlay"><div className="modal"><div className="tabs"><button className={mode==='key'?'tab active':'tab'} onClick={()=>setMode('key')}>{L.add}</button><button className={mode==='sub'?'tab active':'tab'} onClick={()=>setMode('sub')}>{L.subscription}</button></div>{mode==='key'?<><h2>{L.addServer}</h2><input placeholder={L.name} value={name} onChange={e=>setName(e.target.value)}/><textarea placeholder={L.key} value={key} onChange={e=>setKey(e.target.value)}/><div className="row end"><button className="secondary" onClick={()=>setModal(false)}>{L.cancel}</button><button className="primary" onClick={add}>{L.add}</button></div></>:<><h2>{L.subscription}</h2><p className="hint">{L.subscriptionHint}</p><input placeholder="https://example.com/subscription" value={subUrl} onChange={e=>setSubUrl(e.target.value)}/><div className="row end"><button className="secondary" onClick={()=>setModal(false)}>{L.cancel}</button><button className="primary" onClick={importSubscription}>{L.importSub}</button></div></>}</div></div>}
 </main></div>;
}
createRoot(document.getElementById('root')).render(<App/>);
