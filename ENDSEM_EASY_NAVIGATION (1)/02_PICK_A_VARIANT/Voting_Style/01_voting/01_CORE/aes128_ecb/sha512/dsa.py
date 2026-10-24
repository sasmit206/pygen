"""ENDSEM PRACTICE: standalone, Python 3.10+, PyCryptodome + standard library.
Run: python FILE.py [--keygen] [--fast]; --fast is RSA-2048 TEST ONLY.
SOURCE: endsem question + supplied specification + uploaded Labs 1-8 manuals.
ALGORITHMS: SHA-512; AES-128-ECB; RSA-4096 OAEP/SHA256; DSA-2048/256; Paillier additive.
Payload key length: 16 bytes; DES-family bytes include parity. IV: none (ECB).
SEARCH: HMAC-SHA256 equality/time-bucket tokens.
TIMESTAMP: local RSA-2048 PKCS1-v1.5/SHA256 signature on SHA512(envelope) plus time.
STORAGE: pickle; per-owner keys/shares in separate JSON files.
Cipher: PKCS7 padding for ECB/CBC, no padding for stream modes; CFB uses full-block segments, CTR uses full-block counter.
Demo fixed key/IV; REAL random key and IV per record. AES key stored only wrapped.
Signature digest is the selected record hash; ElGamal reduces it mod(p-1).
Schnorr hashes (commitment, record digest) for its challenge; not a standard encoding.
ElGamal/Schnorr DEMO group p=467; REAL fixed RFC3526 2048-bit group.
HE demo n=3127 or p=467; REAL Paillier/RSA ~2048 bits, ElGamal RFC3526.
THRESHOLD: additive n-of-n partial decryption. Owner shares in separate files, no combined key saved.
SAMPLE_COMPAT sums raw IDs; it counts votes only when EVERY value is 1.
ONE_HOT counts enumerated values (for bids/amounts this is a histogram).
PRODUCT mode is multiplicative and does not compute totals or vote counts.
Minimum aggregate size=2. A single-record request is rejected.
TSA and RBAC are local simulations; no network or OS isolation is claimed.
The verifier decrypts the payload. Index search itself does not decrypt it.
Trusted client assumption: no zero-knowledge proof links HE and payload values.
DEMO keys/nonces are predictable for learning; use REAL mode for random parameters.
MD5/SHA1 and DES/3DES are legacy exercises: use only if named in your question.
Pickle loads only your own local files. Never open an untrusted state pickle.
RUBRIC MAP (supplied topic mapping; photo has no full transcript/mark breakdown):
Writeup: client/server -> cast/check; ED -> seal/open_seal + wrap/unwrap;
DSS -> sign/verify; Hash -> digest; Search -> token/search.
Client outputs: hash/IV/ciphertext/wrapped key/signature/HE/time -> cast.
Server outputs: unwrap/decrypt/signature/hash/TSA/window -> check.
All roles: index update/search -> check/search; encrypted aggregate -> aggregate;
partials + aggregate result + individual-record refusal -> decrypt_total.
Output strings are in Zone 1. These labels are NOT a verified paper transcript.
"""
import hashlib, hmac, json, math, pickle, secrets, sqlite3, sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512, SHA1, MD5, SHA3_256
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pkcs1_15, pss, DSS
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

# QUICK EDIT MAP (read this before adapting a question):
# Zone 1 TEXT: rename the story, roles, prompts and the TWO submitted fields.
# Zone 2 ACCOUNTS/GROUPS: edit IDs, passwords, and registered group numbers.
# Zone 4: set demo values, time window, aggregation limits, and storage policy.
# Zone 5: menu labels and which role may run each action.
# Zone 6: crypto adapters; choose an algorithm variant instead of renaming its label.
# Zone 7: cast -> check -> search -> aggregate -> decrypt_total is the data flow.
# For an ID + free-text description + numeric amount, start with Grant_Style.
# After changing crypto/settings, save under a NEW .py filename for fresh state.
# ================= ZONE 1: SKIN / ALL USER-VISIBLE TEXT =================
# Edit TEXT values for wording; fields are the two serialized numeric/group keys.
# Renaming fields is safe here because Zone 7 reads these labels dynamically.
TEXT = {'title': '\nSECURE ELECTRONIC VOTING SYSTEM',
 'main': '\nMAIN MENU',
 'client': '\nVOTER',
 'server': '\nELECTION SERVER',
 'tally': '\nTALLY AUTHORITY',
 'choice': 'Input Choice: ',
 'client_label': 'Voter',
 'server_label': 'Election Server',
 'tally_label': 'Tally Authority',
 'exit': 'Exit',
 'back': 'Back',
 'cast': 'Cast vote',
 'check': 'Verify ballot',
 'search': 'Search index',
 'aggregate': 'Aggregate',
 'decrypt': 'Threshold decrypt',
 'item': '{number} {label}',
 'user': 'Voter ID (voter1/voter2/voter3/voter4): ',
 'group': 'Constituency ID: ',
 'file': 'Payload file path: ',
 'record': 'Ballot ID: ',
 'ids': 'Ballot IDs to aggregate (space separated): ',
 'search_mode': 'Search by 1 Constituency | 2 Time range: ',
 'start': 'Start (dd-mm-yyyy HH:MM:SS IST): ',
 'end': 'End (dd-mm-yyyy HH:MM:SS IST): ',
 'time': 'Submission time (dd-mm-yyyy HH:MM:SS IST): ',
 'shares': 'Authority IDs (quorum {t} of {n}): ',
 'password': 'Password for {owner}: ',
 'login': 'Username: ',
 'keygen': 'Generating and caching keys once; RSA-4096 may take a few seconds...',
 'ready': 'Ready. Mode={mode}; tally={tally}; data={path}',
 'window': 'Valid period: {start} to {end}',
 'sha': 'Output {hash}(hex): {value}',
 'iv': 'Output IV(hex): {value}',
 'ct': 'Output {cipher} CT(hex): {value}',
 'wrap': 'Output {wrap} wrapped payload key(hex, abbreviated): {value}...',
 'sig': 'Output {sig} signature: {value}',
 'he': 'Output {he} ciphertext(s)(hex): {value}',
 'timestamp': 'Output trusted timestamp: {value}',
 'tsa': 'Output timestamp authentication: {status}',
 'accepted': 'Output ballot stored: ID={id}; awaiting server verification',
 'unwrapped': 'Output key unwrap: SUCCESS',
 'decrypted': 'Output payload decrypt: SUCCESS',
 'sig_ok': 'Output {sig} verification: VALID',
 'hash_ok': 'Output {hash} comparison: MATCH',
 'time_ok': 'Output timestamp window: VALID',
 'indexed': 'Output encrypted search index: UPDATED',
 'verified': 'Output ballot verification: ACCEPTED',
 'matches': 'Output matching ballot IDs: {value}',
 'product': 'Output aggregate ciphertext(s)(hex): {value}',
 'part': 'Output authority {owner} partial(s)(hex): {value}',
 'total': 'Output decrypted aggregate: {value}',
 'counts': 'Output counts by {value_name}: {value}',
 'privacy': 'Output individual Paillier votes decrypted: NO',
 'bad': 'Invalid input or operation.',
 'denied': 'Access denied.',
 'duplicate': 'Rejected: this voter has already submitted a ballot.',
 'bounds': 'Rejected: invalid candidate or registered constituency.',
 'sig_bad': 'Rejected: invalid signature.',
 'tsa_bad': 'Rejected: invalid timestamp or bound envelope.',
 'hash_bad': 'Rejected: payload hash mismatch.',
 'late': 'Rejected: outside the valid period.',
 'invalid_ids': 'Select distinct, verified ballot IDs.',
 'no_total': 'Aggregate verified ballots before requesting threshold decryption.',
 'quorum': 'Rejected: insufficient, duplicate or unauthorised shares.',
 'frozen': 'Rejected: aggregate is frozen; start a fresh data folder for another run.',
 'config': 'Saved settings differ. Use a fresh data folder.',
 'stop': '\nStopped.',
 'input_error': 'Operation failed: invalid data, input or ciphertext.',
 'fields': ['CandidateID', 'ConstituencyID'],
 'record_name': 'ballot',
 'value_name': 'candidate',
 'group_name': 'constituency',
 'value_range': 'Rejected: value outside supported range.',
 'bad_share': 'Rejected: unauthorised share request or aggregate modified.',
 'audit_label': 'Auditor',
 'audit': 'Inspect totals status',
 'audit_status': 'Output verified records: {value}',
 'revoked': 'Rejected: account has been revoked.',
 'fast': 'TEST ONLY: --fast uses RSA-2048.',
 'sample': 'SAMPLE_COMPAT = sum of raw IDs/values; ONE_HOT = counts for the enumerated values.',
 'partial_note': 'Output threshold method: {threshold}',
 'error': 'Operation failed: invalid data, input or ciphertext.',
 'value_input': 'Candidate ID (1/2/3): ',
 'no_iv': 'not used (ECB)'}
ALGORITHMS = {'hash': 'SHA-512', 'cipher': 'AES-128-ECB', 'wrap': 'RSA-4096 OAEP/SHA256', 'sig': 'DSA-2048/256', 'he': 'Paillier additive'}

# ================= ZONE 2: ACCOUNTS / ROLES =================
# ACCOUNTS maps login -> (demo password, role); GROUPS maps login -> group ID.
# Keep GROUPS IDs consistent with the values users will submit.
ACCOUNTS = {'voter1': ('123', 'client'), 'voter2': ('123', 'client'), 'voter3': ('123', 'client'), 'voter4': ('123', 'client'), 'server': ('123', 'server'), 'authority1': ('123', 'tally'), 'authority2': ('123', 'tally'), 'authority3': ('123', 'tally')}
GROUPS = {'voter1': 101, 'voter2': 102, 'voter3': 101, 'voter4': 102}
ROLE, LOGIN = None, None
REQUIRE_LOGIN = False  # True: authenticate before entering each role menu.

# ================= ZONE 3: KEYS / PARAMETERS =================
RFC_P = int('''FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6D
F25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6
F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8
A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356
208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E46
2E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6
955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'''.replace('\n', ''), 16)
IST = timezone(timedelta(hours=5, minutes=30))
FORMAT = '%d-%m-%Y %H:%M:%S IST'
FAST = '--fast' in sys.argv  # Test-only RSA-2048 override.

# ================= ZONE 4: FEATURE FLAGS =================
# Adapt VALUES, START/END, and MIN_AGGREGATE_SIZE to the paper's example.
# Keep TALLY_MODE and HE compatible: Paillier sums; ElGamal/RSA multiply.
# A different cipher/hash/signature requires the matching generated variant.
DEMO_MODE = True  # False: random keys/IVs, large HE groups, live window.
TALLY_MODE = 'SAMPLE_COMPAT'  # Sum IDs, per-value histogram, or multiplicative product.
THRESHOLD_MODE = 'additive'  # additive or shamir; see header.
AUTHORITIES = 2  # Number of share holders; add accounts in Zone 2 when increasing.
QUORUM = 2  # additive requires all n; Shamir supports 2 <= t <= n.
TSA_SIGNED = True  # False: unauthenticated clock, labelled explicitly.
TIME_SOURCE = 'demo'  # demo, system, ask; REAL mode forces system if still demo.
START = '03-11-2025 09:00:00 IST'  # Illustrative demo window, not a paper fact.
END = '03-11-2025 17:00:00 IST'  # REAL mode uses now-5 minutes to now+1 hour.
DEMO_LATE = False  # True: intentionally submit after the window.
SEARCH_BUCKET_MINUTES = 1  # Positive integer token granularity.
SEARCH_RANGE = True  # False: allow equality lookup only.
ONE_PER_USER = True  # Reject repeat submissions from the same account.
REVOKED_USERS = []  # Add account IDs to reject new and existing submissions.
VALUES = [1, 2, 3]  # Enumerated candidates, bids, units, or marks for the exercise.
FROM_FILE = False  # True: read exact bytes with the two Zone-1 field names.
MIN_AGGREGATE_SIZE = 2  # Prevent individual-record decryption through the aggregate menu.
STORAGE = 'pickle'  # pickle, json or sqlite; keys always separate owner JSON files.
DATA_DIR = Path(__file__).with_suffix('')  # Own folder; do not reuse after changing crypto/flags.

# ================= ZONE 5: MENUS / PERMISSIONS AS DATA =================
# Reorder menu items here; action names must match Zone 7 functions below.
# PERMISSIONS controls the role check inside each action, not just display.
MENUS = {'main':[('client_label','client'),('server_label','server'),('tally_label','tally'),('exit',None)],
         'client':[('cast','cast'),('back',None)], 'server':[('check','check'),('search','search'),('back',None)],
         'tally':[('aggregate','aggregate'),('decrypt','decrypt_total'),('back',None)]}
PERMISSIONS = {'cast':['client'],'check':['server'],'search':['server'],'aggregate':['tally'],'decrypt_total':['tally']}
# ================= ZONE 6: INDEPENDENT CRYPTOGRAPHIC ADAPTERS =================
# ---- HASH adapter: selected digest, including prehashed signature interface ----
HASH = SHA512
def digest(data): return HASH.new(data).digest()
class Prehashed:
    def __init__(self, data):
        self.data=data; self.digest_size=HASH.digest_size; self.oid=HASH.new().oid
    def digest(self): return self.data
    def new(self, data=b''): return HASH.new(data)

# ---- PAYLOAD adapter: unique IV per record; PKCS7 only for CBC ----
CIPHER_NAME, KEY_BYTES, CIPHER_MODE = ('aes', 16, 'ECB')
def payload_key(number):
    key=bytes(range(KEY_BYTES)) if DEMO_MODE else secrets.token_bytes(KEY_BYTES)
    return DES3.adjust_key_parity(key) if CIPHER_NAME=='des3' else key
def cryptor(key, iv):
    factory={'aes':AES,'des':DES,'des3':DES3}[CIPHER_NAME]; iv=iv[:factory.block_size]
    mode=getattr(factory,'MODE_'+CIPHER_MODE)
    options={} if CIPHER_MODE=='ECB' else ({'nonce':b'', 'initial_value':int.from_bytes(iv,'big')} if CIPHER_MODE=='CTR' else {'iv':iv})
    if CIPHER_MODE=='CFB': options['segment_size']=factory.block_size*8
    return factory.new(key,mode,**options)
def seal(data,key,iv):
    c=cryptor(key,iv); return c.encrypt(pad(data,c.block_size) if CIPHER_MODE in ('CBC','ECB') else data)
def open_seal(data,key,iv):
    c=cryptor(key,iv); raw=c.decrypt(data); return unpad(raw,c.block_size) if CIPHER_MODE in ('CBC','ECB') else raw

# ---- KEY TRANSPORT: RSA-OAEP, SHA256 + MGF1-SHA256 ----
def wrap_setup():
    key=rsa_key('transport',2048 if FAST else 4096)
    save_key('server','transport',key.export_key().hex())
    return key.public_key().export_key().hex()
def wrap_key(key,number):
    return PKCS1_OAEP.new(RSA.import_key(bytes.fromhex(PUBLIC['transport'])),hashAlgo=SHA256,randfunc=rng('wrap'+str(number))).encrypt(key)
def unwrap_key(data):
    key=RSA.import_key(bytes.fromhex(load_key('server','transport')))
    return PKCS1_OAEP.new(key,hashAlgo=SHA256).decrypt(data)

# ---- SIGNATURE: prehashed input uses the selected record hash (no double hashing) ----
SIG_KIND = 'dsa'
def signature_setup(owner,index):
    if SIG_KIND.startswith('rsa'): key=rsa_key('sign-'+owner,2048)
    elif SIG_KIND=='dsa': key=DSA.generate(2048,randfunc=rng('sign-'+owner))
    else: key=ECC.generate(curve='P-256',randfunc=rng('sign-'+owner))
    private=key.export_key(format='DER').hex(); public=key.public_key().export_key(format='DER').hex()
    save_key(owner,'signing',private); return public
def signing_engine(key,salt=0):
    if SIG_KIND=='rsa_v15': return pkcs1_15.new(key)
    if SIG_KIND=='rsa_pss': return pss.new(key,rand_func=rng('pss'+str(salt)))
    return DSS.new(key,'fips-186-3',randfunc=rng('dss'+str(salt)))
def signature_key(raw):
    return (RSA if SIG_KIND.startswith('rsa') else DSA if SIG_KIND=='dsa' else ECC).import_key(bytes.fromhex(raw))
def sign(hashed,owner,salt=0):
    return signing_engine(signature_key(load_key(owner,'signing')),salt).sign(Prehashed(hashed)).hex()
def verify(hashed,signature,owner):
    try: signing_engine(signature_key(PUBLIC['signers'][owner])).verify(Prehashed(hashed),bytes.fromhex(signature)); return True
    except (ValueError,TypeError): return False

# ---- HOMOMORPHIC adapter: additive Paillier OR explicitly multiplicative products ----
HE_KIND = 'paillier'
def he_setup():
    if HE_KIND=='elgamal':
        n=467 if DEMO_MODE else RFC_P; secret=127 if DEMO_MODE else secrets.randbelow(n-3)+2
        spec={'n':n,'g':2,'y':pow(2,secret,n),'bound':n}; modulus=n-1
    else:
        while True:
            a,b=(53,59) if DEMO_MODE else (getPrime(1024),getPrime(1024)); n=a*b; lam=math.lcm(a-1,b-1)
            if a!=b and math.gcd(n,lam)==1 and (HE_KIND=='paillier' or math.gcd(65537,lam)==1): break
        secret=lam*pow(lam,-1,n) if HE_KIND=='paillier' else pow(65537,-1,lam)
        modulus=n*lam if HE_KIND=='paillier' else lam
        spec={'n':n,'g':n+1,'e':65537,'bound':n}
    threshold_setup(secret,modulus); return spec
def he_encrypt(value,randomizer):
    h=PUBLIC['he']; n=h['n']; require(0<=value<n,'value_range')
    if HE_KIND=='paillier': return pow(n+1,value,n*n)*pow(randomizer,n,n*n)%(n*n)
    if HE_KIND=='rsa': return pow(value,h['e'],n)
    require(value>0,'value_range'); return [pow(h['g'],randomizer,n),value*pow(h['y'],randomizer,n)%n]
def he_combine(rows):
    n=PUBLIC['he']['n']; result=[]
    for col in zip(*rows):
        if HE_KIND=='elgamal': result.append([math.prod(c[0] for c in col)%n,math.prod(c[1] for c in col)%n])
        else: result.append(math.prod(col)%(n*n if HE_KIND=='paillier' else n))
    return result
def he_part(c,share):
    n=PUBLIC['he']['n']; return pow(c[0] if HE_KIND=='elgamal' else c,share,n*n if HE_KIND=='paillier' else n)
def he_finish(c,parts):
    n=PUBLIC['he']['n']; u=math.prod(parts)%(n*n if HE_KIND=='paillier' else n)
    if HE_KIND=='paillier': require((u-1)%n==0,'bad'); return (u-1)//n
    return c[1]*pow(u,-1,n)%n if HE_KIND=='elgamal' else u

# ---- THRESHOLD: additive n-of-n partials, or Shamir with temporary reconstruction ----
def threshold_setup(secret,modulus):
    if THRESHOLD_MODE=='additive':
        shares=[123+i if DEMO_MODE else secrets.randbelow(modulus) for i in range(AUTHORITIES-1)]
        shares.append((secret-sum(shares))%modulus); field=0
    else:
        field=(1<<127)-1 if DEMO_MODE else getPrime(secret.bit_length()+64)
        coefficients=[secret]+[number_rng('coef'+str(i),field-1)+1 for i in range(1,QUORUM)]
        shares=[sum(c*pow(x,j,field) for j,c in enumerate(coefficients))%field for x in range(1,AUTHORITIES+1)]
    for i,share in enumerate(shares,1): save_key('authority'+str(i),'share',{'x':i,'value':share,'field':field})
def reconstruct(shares):
    p=shares[0]['field']; total=0
    for s in shares:
        num=den=1
        for o in shares:
            if o['x']!=s['x']: num=num*(-o['x'])%p; den=den*(s['x']-o['x'])%p
        total=(total+s['value']*num*pow(den,-1,p))%p
    return total
def threshold_result(owners):
    request('decrypt_total')
    require(STATE['aggregate'] is not None,'no_total')
    require(len(owners)>=QUORUM and len(owners)==len(set(owners)) and all(x.isdigit() and 1<=int(x)<=AUTHORITIES for x in owners),'quorum')
    a=STATE['aggregate']; require(hmac.compare_digest(a['seal'],aggregate_seal(a)),'bad_share')
    shares=[]
    for number in owners:
        owner='authority'+number
        require(owner in ACCOUNTS and ACCOUNTS[owner][1]=='tally' and hmac.compare_digest(ask('password',owner=owner),ACCOUNTS[owner][0]),'quorum')
        shares.append(load_key(owner,'share'))
    if THRESHOLD_MODE=='shamir':
        secret=reconstruct(shares); result=[he_finish(c,[he_part(c,secret)]) for c in a['ciphertexts']]; del secret
    else:
        parts=[[he_part(c,s['value']) for c in a['ciphertexts']] for s in shares]
        for owner,part in zip(owners,parts): out('part',owner=owner,value=hexify(part))
        result=[he_finish(c,list(column)) for c,column in zip(a['ciphertexts'],zip(*parts))]
    return result

# ---- SEARCH: opaque equality tokens and one token per time bucket ----
SSE_KIND = 'hmac'
def token(field,value):
    key=bytes.fromhex(load_key('server','search')); data=canonical([field,str(value)])
    if SSE_KIND=='hmac': return hmac.new(key,data,hashlib.sha256).hexdigest()
    c=AES.new(SHA512.new(key+b'index-SIV').digest(),AES.MODE_SIV); encrypted,tag=c.encrypt_and_digest(data); return (tag+encrypted).hex()
def bucket(when): return int(when.timestamp())//(60*SEARCH_BUCKET_MINUTES)

# ---- TIMESTAMP: signed local TSA simulation or explicitly unauthenticated clock ----
def stamp(envelope,when):
    message={'hash':SHA512.new(canonical(envelope)).hexdigest(),'time':when.isoformat()}
    if not TSA_SIGNED: return message,''
    key=RSA.import_key(bytes.fromhex(load_key('tsa','signing')))
    return message,pkcs1_15.new(key).sign(SHA256.new(canonical(message))).hex()
def check_stamp(record):
    if TSA_SIGNED:
        try: pkcs1_15.new(RSA.import_key(bytes.fromhex(PUBLIC['tsa']))).verify(SHA256.new(canonical(record['timestamp'])),bytes.fromhex(record['tsa_signature']))
        except (ValueError,TypeError): raise ValueError(TEXT['tsa_bad'])
    require(record['timestamp']['hash']==SHA512.new(canonical(record['packet'])).hexdigest(),'tsa_bad')
def time_now(number):
    when=datetime.fromisoformat(PUBLIC['start'])+timedelta(minutes=number-1) if TIME_SOURCE=='demo' and DEMO_MODE else datetime.now(IST)
    if TIME_SOURCE=='ask': when=parse_time(ask('time'))
    return datetime.fromisoformat(PUBLIC['end'])+timedelta(minutes=1) if DEMO_LATE else when

# ================= ZONE 7: STORAGE / GENERIC PIPELINE / MAIN =================
def out(key,**values): print(TEXT[key].format(**(TEXT|ALGORITHMS|values)))
def ask(label,**values): return input(TEXT[label].format(**(TEXT|ALGORITHMS|values))).strip()
def require(condition,label):
    if not condition: raise ValueError(TEXT[label])
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def hexify(value): return [hexify(x) for x in value] if isinstance(value,(tuple,list)) else hex(value)
def rng(label):
    counter=0
    def take(size):
        nonlocal counter
        data=b''
        while len(data)<size: data+=hashlib.sha256((label+str(counter)).encode()).digest(); counter+=1
        return data[:size]
    take.label=label
    return take if DEMO_MODE else secrets.token_bytes
def number_rng(label,limit): return int.from_bytes(rng(label)((limit.bit_length()+7)//8+16),'big')%limit
def rsa_key(label,bits): return RSA.generate(bits,randfunc=rng(label))
def store(path,value):
    path.parent.mkdir(parents=True,exist_ok=True); temp=path.with_suffix('.tmp')
    temp.write_bytes(canonical(value)); temp.replace(path)
def load(path): return json.loads(path.read_bytes())
def load_key(owner,name): return load(DATA_DIR/owner/(name+'.json'))
def save_key(owner,name,value): store(DATA_DIR/owner/(name+'.json'),value)
def save():
    path=DATA_DIR/('records.'+STORAGE)
    if STORAGE=='sqlite':
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, data BLOB)')
            db.execute('INSERT OR REPLACE INTO state VALUES(1,?)',(canonical(STATE),))
    elif STORAGE=='json': store(path,STATE)
    else: path.write_bytes(pickle.dumps(STATE))
def restore():
    path=DATA_DIR/('records.'+STORAGE)
    if STORAGE=='sqlite':
        with sqlite3.connect(path) as db: state=json.loads(db.execute('SELECT data FROM state WHERE id=1').fetchone()[0])
    elif STORAGE=='json': state=load(path)
    else: state=pickle.loads(path.read_bytes())
    state['records']={int(k):v for k,v in state['records'].items()}; return state
def parse_time(text): return datetime.strptime(text,FORMAT).replace(tzinfo=IST)
def request(action): require(ROLE in PERMISSIONS[action], 'denied')
def aggregate_seal(a):
    message={k:v for k,v in a.items() if k!='seal'}
    return hmac.new(bytes.fromhex(load_key('server','search')),canonical(message),hashlib.sha256).hexdigest()
def setup():
    global PUBLIC,STATE
    require(SEARCH_BUCKET_MINUTES>0 and MIN_AGGREGATE_SIZE>=2 and VALUES and len(VALUES)==len(set(VALUES)),'bad')
    require(2<=QUORUM<=AUTHORITIES and (THRESHOLD_MODE!='additive' or QUORUM==AUTHORITIES),'bad')
    require(HE_KIND=='paillier' or TALLY_MODE=='PRODUCT','bad')
    configuration=[ALGORITHMS,DEMO_MODE,FAST,TALLY_MODE,THRESHOLD_MODE,QUORUM,AUTHORITIES,VALUES,SEARCH_BUCKET_MINUTES,STORAGE,TSA_SIGNED,TIME_SOURCE,START,END,TEXT['fields']]
    path=DATA_DIR/'public.json'
    if path.exists():
        PUBLIC=load(path); require(PUBLIC['configuration']==configuration,'config'); STATE=restore(); return
    DATA_DIR.mkdir(parents=True,exist_ok=True); out('keygen')
    transport=wrap_setup(); he=he_setup(); signers={owner:signature_setup(owner,i) for i,owner in enumerate(GROUPS)}
    save_key('server','search',rng('search')(32).hex())
    tsa=rsa_key('tsa',2048) if TSA_SIGNED else None
    if tsa: save_key('tsa','signing',tsa.export_key().hex())
    now=datetime.now(IST); start=parse_time(START) if DEMO_MODE else now-timedelta(minutes=5); end=parse_time(END) if DEMO_MODE else now+timedelta(hours=1)
    PUBLIC={'configuration':configuration,'transport':transport,'he':he,'signers':signers,'tsa':tsa.public_key().export_key().hex() if tsa else '', 'start':start.isoformat(),'end':end.isoformat()}
    STATE={'records':{},'index':{},'aggregate':None}; store(path,PUBLIC); save()
def cast():
    request('cast'); require(STATE['aggregate'] is None,'frozen')
    owner=LOGIN if REQUIRE_LOGIN else ask('user'); require(owner in GROUPS,'denied'); require(owner not in REVOKED_USERS,'revoked')
    require(not ONE_PER_USER or all(r['owner']!=owner for r in STATE['records'].values()),'duplicate')
    if FROM_FILE:
        raw=Path(ask('file')).read_bytes(); fields=dict(part.split('=',1) for part in raw.decode().split(';'))
        value,group=(int(fields[k]) for k in TEXT['fields'])
    else:
        value,group=int(ask('value_input')),int(ask('group')); raw=';'.join(f'{k}={v}' for k,v in zip(TEXT['fields'],[value,group])).encode()
    require(value in VALUES and group==GROUPS[owner],'bounds')
    number=len(STATE['records'])+1; key=payload_key(number)
    iv=bytes(range(16+16*number,32+16*number)) if DEMO_MODE and number<=2 else rng('iv'+str(number))(16)
    hashed=digest(raw); ct=seal(raw,key,iv); wrapped=wrap_key(key,number)
    entries=[int(value==c) for c in VALUES] if TALLY_MODE=='ONE_HOT' else [value]; encrypted=[]
    for i,entry in enumerate(entries):
        n=PUBLIC['he']['n']; r=(number+1+i*10)%n if DEMO_MODE else secrets.randbelow(n-2)+1
        while r==0 or math.gcd(r,n)!=1: r=(r+1)%n
        encrypted.append(he_encrypt(entry,r))
    when=time_now(number)
    packet={'id':number,'owner':owner,'hash':hashed.hex(),'iv':iv.hex(),'ct':ct.hex(),'wrapped':wrapped.hex(), 'signature':sign(hashed,owner,number),'he':encrypted,'group_token':token('group',group),'time_token':token('time',bucket(when))}
    packet['envelope_signature']=sign(digest(canonical(packet)),owner,number+100)
    timestamp,tsa_signature=stamp(packet,when)
    STATE['records'][number]={'owner':owner,'packet':packet,'timestamp':timestamp,'tsa_signature':tsa_signature,'verified':False}; save()
    for label,data in [('sha',hashed.hex()),('iv',TEXT['no_iv'] if CIPHER_MODE=='ECB' else iv[:8 if CIPHER_NAME in ('des','des3') else 16].hex()),('ct',ct.hex()),('wrap',wrapped.hex()[:64]),('sig',packet['signature']),('he',hexify(encrypted)),('timestamp',when.strftime(FORMAT))]: out(label,value=data)
    out('accepted',id=number); return number

def validate(record):
    p=dict(record['packet']); owner=record['owner']; require(owner==p['owner'] and owner in GROUPS and owner not in REVOKED_USERS,'denied')
    check_stamp(record); signature=p.pop('envelope_signature')
    require(verify(digest(canonical(p)),signature,owner),'sig_bad'); require(verify(bytes.fromhex(p['hash']),p['signature'],owner),'sig_bad')
    raw=open_seal(bytes.fromhex(p['ct']),unwrap_key(bytes.fromhex(p['wrapped'])),bytes.fromhex(p['iv']))
    require(hmac.compare_digest(digest(raw).hex(),p['hash']),'hash_bad')
    fields=dict(part.split('=',1) for part in raw.decode().split(';'))
    require(int(fields[TEXT['fields'][0]]) in VALUES and int(fields[TEXT['fields'][1]])==GROUPS[owner],'bounds')
    when=datetime.fromisoformat(record['timestamp']['time'])
    require(datetime.fromisoformat(PUBLIC['start'])<=when<=datetime.fromisoformat(PUBLIC['end']),'late')
    require(p['group_token']==token('group',GROUPS[owner]) and p['time_token']==token('time',bucket(when)),'tsa_bad'); return when

def check():
    request('check'); number=int(ask('record')); record=STATE['records'][number]
    require(number==record['packet']['id'],'bad'); validate(record); record['verified']=True
    for tag in ['group_token','time_token']:
        ids=STATE['index'].setdefault(record['packet'][tag],[])
        if number not in ids: ids.append(number)
    save()
    for label in ['unwrapped','decrypted','sig_ok','hash_ok','tsa','time_ok','indexed','verified']: out(label,status='VALID' if TSA_SIGNED else 'UNSIGNED clock')

def search():
    request('search'); mode=ask('search_mode')
    if mode=='1': ids=set(STATE['index'].get(token('group',int(ask('group'))),[]))
    elif mode=='2' and SEARCH_RANGE:
        start,end=parse_time(ask('start')),parse_time(ask('end')); require(start<=end and end-start<=timedelta(days=7),'bad'); ids=set()
        for t in range(bucket(start),bucket(end)+1): ids.update(STATE['index'].get(token('time',t),[]))
        ids={i for i in ids if start<=datetime.fromisoformat(STATE['records'][i]['timestamp']['time'])<=end}
    else: raise ValueError(TEXT['bad'])
    out('matches',value=sorted(ids)); return sorted(ids)

def aggregate():
    request('aggregate'); require(STATE['aggregate'] is None,'frozen'); ids=list(map(int,ask('ids').split()))
    require(len(ids)>=MIN_AGGREGATE_SIZE and len(ids)==len(set(ids)) and all(i in STATE['records'] and STATE['records'][i]['verified'] for i in ids),'invalid_ids')
    limit=pow(max(VALUES),len(ids)) if TALLY_MODE=='PRODUCT' else len(ids)*(1 if TALLY_MODE=='ONE_HOT' else max(VALUES)); require(limit<PUBLIC['he']['bound'],'value_range')
    rows=[]
    for i in ids:
        r=STATE['records'][i]; validate(r); require(r['packet']['id']==i,'bad'); rows.append(r['packet']['he'])
        require(len(rows[-1])==(len(VALUES) if TALLY_MODE=='ONE_HOT' else 1),'bad')
    a={'ids':ids,'ciphertexts':he_combine(rows)}; a['seal']=aggregate_seal(a); STATE['aggregate']=a; save()
    out('product',value=hexify(a['ciphertexts'])); out('privacy')

def decrypt_total():
    request('decrypt_total'); require(STATE['aggregate'] is not None,'no_total'); owners=ask('shares',t=QUORUM,n=AUTHORITIES).split()
    values=threshold_result(owners); out('partial_note',threshold=THRESHOLD_MODE)
    out('counts' if TALLY_MODE=='ONE_HOT' else 'total',value=dict(zip(VALUES,values)) if TALLY_MODE=='ONE_HOT' else values[0]); out('privacy'); return values

def audit_status():
    request('audit_status'); out('audit_status',value=sum(r['verified'] for r in STATE['records'].values()))
def menu(name):
    global ROLE,LOGIN
    while True:
        out(name)
        for i,(label,_) in enumerate(MENUS[name],1): out('item',number=i,label=TEXT[label])
        try:
            choice=int(ask('choice')); require(1<=choice<=len(MENUS[name]),'bad'); handler=MENUS[name][choice-1][1]
            if handler is None: return
            if name=='main':
                ROLE,LOGIN=handler,None
                try:
                    if REQUIRE_LOGIN:
                        LOGIN=ask('login'); account=ACCOUNTS.get(LOGIN)
                        require(account and account[1]==ROLE and hmac.compare_digest(ask('password',owner=LOGIN),account[0]),'denied')
                    menu(handler)
                finally: ROLE,LOGIN=None,None
            else: globals()[handler]()
        except (ValueError,KeyError,OSError,TypeError,UnicodeError,IndexError) as error:
            out(next((k for k,v in TEXT.items() if isinstance(v,str) and v==str(error)),'error'))
def main():
    setup(); out('title'); out('ready',mode='DEMO' if DEMO_MODE else 'REAL',tally=TALLY_MODE,path=DATA_DIR)
    out('window',start=datetime.fromisoformat(PUBLIC['start']).strftime(FORMAT),end=datetime.fromisoformat(PUBLIC['end']).strftime(FORMAT))
    if FAST: out('fast')
    if '--keygen' not in sys.argv: menu('main')
if __name__=='__main__':
    try: main()
    except (KeyboardInterrupt,EOFError): out('stop')
