import {domainToASCII} from 'node:url';

const IANA_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json';
const bootstrapCache = {at: 0, services: []};
const answerCache = new Map();
const EXPIRING_DAYS = 30;

export function normalizeDomain(input) {
  let raw = String(input ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (!raw) throw new Error('domain_required');
  if (raw.includes('://') || raw.includes('@') || /[/?#]/.test(raw)) throw new Error('domain_only_required');
  const ascii = domainToASCII(raw);
  if (!ascii || ascii.length > 253 || !ascii.includes('.')) throw new Error('invalid_domain');
  for (const label of ascii.split('.')) {
    if (!label || label.length > 63 || !/^[a-z0-9-]+$/i.test(label) || label.startsWith('-') || label.endsWith('-')) throw new Error('invalid_domain');
  }
  return ascii;
}

const canon = v => String(v ?? '').trim().replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').toLowerCase();
export function normalizeStatuses(list) { return [...new Set((Array.isArray(list) ? list : []).map(canon).filter(Boolean))]; }

function eventDate(events, actions) {
  const wanted = new Set(actions.map(canon));
  for (const e of Array.isArray(events) ? events : []) {
    if (wanted.has(canon(e?.eventAction)) && e?.eventDate && !Number.isNaN(Date.parse(e.eventDate))) return new Date(e.eventDate).toISOString();
  }
  return null;
}
function creationDate(events) {
  const dates = (Array.isArray(events) ? events : []).filter(e => ['registration','reregistration'].includes(canon(e?.eventAction))).map(e => e?.eventDate).filter(d => d && !Number.isNaN(Date.parse(d))).map(d => new Date(d).toISOString()).sort();
  return dates[0] ?? null;
}
function registrarName(entities) {
  const entity = (Array.isArray(entities) ? entities : []).find(e => Array.isArray(e?.roles) && e.roles.map(canon).includes('registrar'));
  if (!entity) return null;
  if (Array.isArray(entity.vcardArray?.[1])) {
    const fn = entity.vcardArray[1].find(row => Array.isArray(row) && String(row[0]).toLowerCase() === 'fn');
    if (fn?.[3]) return String(fn[3]).trim();
  }
  const id = (Array.isArray(entity.publicIds) ? entity.publicIds : []).find(p => /registrar/i.test(String(p?.type ?? '')) && p?.identifier);
  return id?.identifier ? `IANA Registrar ID ${id.identifier}` : (entity.handle ?? null);
}
function nameservers(items) { return [...new Set((Array.isArray(items) ? items : []).map(n => n?.ldhName || n?.unicodeName).filter(Boolean).map(x => String(x).replace(/\.$/, '').toLowerCase()))].sort(); }
function daysToExpiry(expiresAt, now) { return expiresAt && !Number.isNaN(Date.parse(expiresAt)) ? Math.ceil((Date.parse(expiresAt)-now)/86400000) : null; }

export function deriveState({status, expiresAt, now = Date.now(), expiringDays = EXPIRING_DAYS}) {
  const s = normalizeStatuses(status);
  if (s.includes('pending delete')) return 'PENDING_DELETE';
  if (s.includes('redemption period')) return 'REDEMPTION';
  if (s.includes('client hold') || s.includes('server hold')) return 'HOLD';
  const d = daysToExpiry(expiresAt, now);
  if (d !== null && d >= 0 && d <= expiringDays) return 'EXPIRING';
  return 'REGISTERED';
}

function unknown(domain, source, reason, now) { return {domain,state:'UNKNOWN',registered:null,registrar:null,created_at:null,expires_at:null,days_to_expiry:null,statuses:[],nameservers:[],authoritative_rdap:source,confidence:'LOW',evidence:[reason],checked_at:new Date(now).toISOString()}; }
function unregistered(domain, source, now) { return {domain,state:'UNREGISTERED',registered:false,registrar:null,created_at:null,expires_at:null,days_to_expiry:null,statuses:[],nameservers:[],authoritative_rdap:source,confidence:'HIGH',evidence:['Authoritative RDAP returned HTTP 404 for the domain'],checked_at:new Date(now).toISOString()}; }

async function bootstrap(fetchImpl, now) {
  const ttl = Number(process.env.DOMAINSTATE_BOOTSTRAP_TTL_MS || 21600000);
  if (bootstrapCache.services.length && now-bootstrapCache.at < ttl) return bootstrapCache.services;
  const r = await fetchImpl(IANA_BOOTSTRAP,{headers:{'user-agent':'DOMAINSTATE/1.0'},signal:AbortSignal.timeout(8000)});
  if (!r.ok) throw new Error(`bootstrap_http_${r.status}`);
  const j = await r.json();
  if (!Array.isArray(j?.services) || !j.services.length) throw new Error('bootstrap_empty');
  bootstrapCache.at = now; bootstrapCache.services = j.services; return j.services;
}
export function rdapBaseFor(domain, services) {
  const tld = domain.split('.').at(-1).toLowerCase();
  for (const entry of services) {
    const tlds = Array.isArray(entry?.[0]) ? entry[0].map(x=>String(x).toLowerCase()) : [];
    const urls = Array.isArray(entry?.[1]) ? entry[1] : [];
    if (tlds.includes(tld) && urls.length) return String(urls[0]);
  }
  return null;
}

export async function inspectDomain(input,{fetchImpl=fetch,now=Date.now()}={}) {
  const domain = normalizeDomain(input);
  const cached = answerCache.get(domain); if (cached && cached.expires > now) return {...cached.value,cache:'HIT'};
  let services; try { services = await bootstrap(fetchImpl,now); } catch(e) { return unknown(domain,IANA_BOOTSTRAP,`IANA RDAP bootstrap unavailable: ${e.message}`,now); }
  const base = rdapBaseFor(domain,services); if (!base) return unknown(domain,IANA_BOOTSTRAP,'No authoritative RDAP bootstrap service found for the TLD',now);
  const source = new URL(`domain/${encodeURIComponent(domain)}`,base.endsWith('/')?base:`${base}/`).toString();
  let r; try { r = await fetchImpl(source,{headers:{accept:'application/rdap+json, application/json;q=0.9','user-agent':'DOMAINSTATE/1.0'},redirect:'follow',signal:AbortSignal.timeout(8000)}); } catch(e) { return unknown(domain,source,`Authoritative RDAP request failed: ${e.message}`,now); }
  let value,ttl;
  if (r.status===404) { value=unregistered(domain,source,now); ttl=Number(process.env.DOMAINSTATE_NEGATIVE_TTL_MS||60000); }
  else if (r.ok) {
    let body; try { body=await r.json(); } catch { return unknown(domain,source,'Authoritative RDAP returned non-JSON content',now); }
    if (canon(body?.objectClassName)!=='domain') return unknown(domain,source,'RDAP response did not identify itself as a domain object',now);
    const statuses=normalizeStatuses(body.status); const created=creationDate(body.events); const expires=eventDate(body.events,['expiration'])||eventDate(body.events,['registrar expiration']);
    value={domain,state:deriveState({status:statuses,expiresAt:expires,now,expiringDays:Number(process.env.DOMAINSTATE_EXPIRING_DAYS||30)}),registered:true,registrar:registrarName(body.entities),created_at:created,expires_at:expires,days_to_expiry:daysToExpiry(expires,now),statuses,nameservers:nameservers(body.nameservers),authoritative_rdap:source,confidence:'HIGH',evidence:['Authoritative RDAP returned a domain object',...(statuses.length?[`RDAP statuses: ${statuses.join(', ')}`]:[]),...(expires?[`RDAP expiration event: ${expires}`]:[])],checked_at:new Date(now).toISOString()}; ttl=Number(process.env.DOMAINSTATE_POSITIVE_TTL_MS||300000);
  } else { value=unknown(domain,source,`Authoritative RDAP returned HTTP ${r.status}; not enough evidence for REGISTERED or UNREGISTERED`,now); ttl=15000; }
  answerCache.set(domain,{expires:now+ttl,value}); return {...value,cache:'MISS'};
}
export function _resetForTests(){bootstrapCache.at=0;bootstrapCache.services=[];answerCache.clear();}
