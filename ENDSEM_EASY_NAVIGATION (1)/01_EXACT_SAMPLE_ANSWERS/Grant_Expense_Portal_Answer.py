"""STRUCTURED-RECORD ENDSEM ANSWER. Python 3.10+, PyCryptodome.
SOURCE: uploaded Secure Grant Expense Portal endsem paper, then generalized skins.
Default exact algorithms AES-192-CBC/PKCS7, Paillier n=3127, MD5, RSA-v1.5.
One file contains the menus, keys, persistent record store and verification pipeline.
Hash/signature cover canonical stored record {ID, IV, encrypted description,
Paillier ciphertext}; therefore reviewer verifies tampering without decrypting
any individual amount. Finance verifies selected records before combining their
Paillier ciphertexts, then decrypts only the combined ciphertext (minimum 2).
A verified reviewer is expressly allowed to decrypt a DESCRIPTION and display
its UTF-8 bytes in hexadecimal. Amounts never enter the AES plaintext or index.
Grant ID is intentionally public, descriptions and numeric values stay encrypted.
For DEMO n=3127, amounts <=1000, at most three selections keep total below n.
For larger values, set DEMO_MODE=False and start with a fresh state directory.
DEMO salts/nonces/keygen are reproducible; REAL mode uses random keys and IVs.
MD5/SHA1/DES/3DES/RSA-v1.5 are syllabus/legacy options, not production choices.
Role-menu permission checks are local; optional login is demonstration only.
The code is a teaching simulation, not a deployed grant or voting service.
"""
import hashlib,hmac,json,math,pickle,secrets,sqlite3,sys
from pathlib import Path
from Crypto.Cipher import AES,DES,DES3
from Crypto.Hash import MD5,SHA1,SHA256,SHA512,SHA3_256
from Crypto.PublicKey import RSA,DSA,ECC
from Crypto.Signature import pkcs1_15,pss,DSS
from Crypto.Util.Padding import pad,unpad
from Crypto.Util.number import getPrime

# QUICK EDIT MAP (read this before adapting a question):
# Zone 1 CONFIG['story']: title, three role names, ID/description/amount
# prompts, and singular record noun. TEXT holds every menu/output label.
# Zone 2 MENUS/PERMISSIONS: reorder actions and edit demo passwords.
# Zone 4: demo/real mode, login flag, amount/selection caps and state folder.
# Zone 5: submit -> verified_record -> aggregate -> finalize is the data flow.
# Choose a matching variant for cipher/hash/signature; changing only its
# printed label DOES NOT switch the algorithm. Allowed variants are under
# 02_PICK_A_VARIANT/Grant_Style in the ZIP.
# Save an adapted answer as a NEW .py filename so it gets a fresh state folder.
# ================= ZONE 1: EXAM STORY + ALL MENU/OUTPUT TEXT =================
# Rename the eight CONFIG['story'] values below for a new paper's wording.
# The stored schema remains id + encrypted description + encrypted amount.
# A new field or different data type also needs submit(), record_body(),
# verified_record(), and the display/aggregate path adjusted in Zone 5.
CONFIG={'story': {'title': 'SECURE GRANT EXPENSE PORTAL',
           'client': 'Researcher',
           'server': 'Reviewer',
           'finance': 'Finance Officer',
           'id': 'Grant ID',
           'description': 'Grant Description',
           'amount': 'Grant Amount',
           'record': 'grant'},
 'cipher': 'aes192_cbc',
 'hash': 'md5',
 'sig': 'rsa_v15',
 'storage': 'json',
 'index': 'hmac'}
S=CONFIG['story']
HASH_MODULE={'md5':MD5,'sha1':SHA1,'sha256':SHA256,'sha512':SHA512,'sha3_256':SHA3_256}[CONFIG['hash']]
CIPHER_FAMILY,CIPHER_MODE=CONFIG['cipher'].split('_')
CIPHER_FACTORY=DES3 if CIPHER_FAMILY=='3des' else DES if CIPHER_FAMILY=='des' else AES
KEY_BYTES={'aes128':16,'aes192':24,'aes256':32,'des':8,'3des':24}[CIPHER_FAMILY]
CIPHER_LABEL=CIPHER_FAMILY.upper().replace('AES','AES-').replace('3DES','3DES')+'-'+CIPHER_MODE.upper()
HASH_LABEL=CONFIG['hash'].upper().replace('SHA3_','SHA3-').replace('SHA','SHA-')
SIG_LABEL={'rsa_v15':'RSA','rsa_pss':'RSA-PSS','elgamal':'ElGamal','schnorr':'Schnorr','dsa':'DSA','ecdsa':'ECDSA'}[CONFIG['sig']]
TEXT={'main':'MAIN MENU','client_menu':S['client'].upper()+' MENU','review_menu':S['server'].upper()+' MENU',
      'finance_menu':'FINANCE MENU','choice':'Input Choice: ','back':'Back','exit':'Exit',
      'submit':'Submit '+S['record']+' details','view':'View submitted details','verify':'Verify',
      'search':'Search index','hex':'View decrypted hex','aggregate':'Aggregate','finalize':'Verify and decrypt aggregate',
      'id':S['id']+': ','description':S['description']+': ','amount':S['amount']+': ',
      'ids':S['id']+'s (comma or space separated): ',
      'keygen':'Generating separate signing, reviewer and finance keys...',
      'ready':'Ready. Saved records: {count}; storage={storage}',
      'iv':'Output IV(hex): {value}', 'ct':'Output {cipher} CT(hex): {value}',
      'paillier':'Output Paillier amount CT(hex): {value}',
      'hash':'Output {hash}(hex): {value}', 'signature':'Output {sig} signature: {value}',
      'stored':'Output: {id} submitted and stored',
      'row':'Output: {id} | CT: {ct} | Paillier CT: {he} | {hash}: {digest}',
      'empty':'Output: No submitted records.',
      'verified':'Output: {sig} signature valid; {hash} matches; {id} verified',
      'found':'Output: Record found: {id} (contents remain encrypted)',
      'missing':'Output: Record not found: {id}',
      'decrypted':'Output: {cipher} decrypted text: {value}',
      'hex_result':'Output: Decrypted hex: {value}',
      'product':'Output: Product of Paillier ciphertexts mod n^2 = {value}',
      'total':'Output: Signatures valid; aggregate decrypted = {value}',
      'private':'Output: Individual amounts not decrypted',
      'invalid':'Rejected: invalid or unauthorized input.',
      'tampered':'Rejected: invalid signature or modified record.',
      'frozen':'Rejected: verify/decrypt the current aggregate before making another.',
      'quit':'Exit'}

def say(tag,**values):print(TEXT[tag].format(**({'hash':HASH_LABEL,'cipher':CIPHER_LABEL,'sig':SIG_LABEL}|values)))
def ask(tag):return input(TEXT[tag]).strip()
def require(ok,message):
    if not ok:raise ValueError(message)
def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
def rng(label):
    counter=0
    def take(length):
        nonlocal counter
        out=b''
        while len(out)<length:out+=hashlib.sha256((label+':'+str(counter)).encode()).digest();counter+=1
        return out[:length]
    take.label=label
    return take if DEMO_MODE else secrets.token_bytes

# ================= ZONE 2: MENU ROLES / PERMISSIONS =================
# MENU labels derive from Zone 1; action keys must match Zone 6 dispatch.
# PERMISSIONS is checked within every action. Demo passwords are local only.
MENUS={'main':[('client',S['client']),('review',S['server']),('finance',S['finance']),('exit',TEXT['exit'])],
       'client':[('submit',TEXT['submit']),('view',TEXT['view']),('back',TEXT['back'])],
       'review':[('verify',TEXT['verify']),('search',TEXT['search']),('hex',TEXT['hex']),('back',TEXT['back'])],
       'finance':[('aggregate',TEXT['aggregate']),('finalize',TEXT['finalize']),('back',TEXT['back'])]}
PERMISSIONS={'submit':'client','view':'client','verify':'review','search':'review','hex':'review','aggregate':'finance','finalize':'finance'}
ROLE=None
LOGIN=False
DEMO_PASSWORDS={'client':'123','review':'123','finance':'123'}
def permission(action):require(ROLE==PERMISSIONS[action],'Access denied for this role.')

# ================= ZONE 3: KEYS / CRYPTO ADAPTERS =================
def save_key(owner,name,value):
    folder=DATA_DIR/'keys'/owner;folder.mkdir(parents=True,exist_ok=True)
    (folder/(name+'.json')).write_bytes(canonical(value))
def load_key(owner,name):return json.loads((DATA_DIR/'keys'/owner/(name+'.json')).read_bytes())
def digest(raw):return HASH_MODULE.new(raw)
def payload_key():
    key=rng('description-key')(KEY_BYTES)
    return DES3.adjust_key_parity(key) if CIPHER_FAMILY=='3des' else key
def iv_for(record_id):return rng('description-IV-'+record_id)(CIPHER_FACTORY.block_size)
def payload_cipher(key,iv):
    mode=getattr(CIPHER_FACTORY,'MODE_'+CIPHER_MODE.upper())
    opts={} if CIPHER_MODE=='ecb' else ({'nonce':b'','initial_value':int.from_bytes(iv,'big')} if CIPHER_MODE=='ctr' else {'iv':iv})
    if CIPHER_MODE=='cfb':opts['segment_size']=CIPHER_FACTORY.block_size*8
    return CIPHER_FACTORY.new(key,mode,**opts)
def encrypt_text(raw,iv):
    cipher=payload_cipher(bytes.fromhex(load_key('review','description')),iv)
    return cipher.encrypt(pad(raw,cipher.block_size) if CIPHER_MODE in ('ecb','cbc') else raw)
def decrypt_text(ct,iv):
    cipher=payload_cipher(bytes.fromhex(load_key('review','description')),iv);raw=cipher.decrypt(ct)
    return unpad(raw,cipher.block_size) if CIPHER_MODE in ('ecb','cbc') else raw

def he_setup():
    if DEMO_MODE:p,q=53,59
    else:
        while True:
            p,q=getPrime(1024),getPrime(1024)
            if p!=q and math.gcd(p*q,math.lcm(p-1,q-1))==1:break
    n=p*q;lam=math.lcm(p-1,q-1);mu=pow(lam,-1,n)
    save_key('finance','paillier',[lam,mu]);return {'n':n,'g':n+1}
def he_encrypt(amount,record_id):
    n=PUBLIC['he']['n'];require(0<=amount<n,'Amount outside Paillier plaintext range.')
    r=int.from_bytes(rng('he-'+record_id)(2*(n.bit_length()//8+1)),'big')%(n-1)+1
    while math.gcd(r,n)!=1:r=r%n+1
    return pow(n+1,amount,n*n)*pow(r,n,n*n)%(n*n)
def he_decrypt_aggregate(value):
    n=PUBLIC['he']['n'];lam,mu=load_key('finance','paillier')
    return ((pow(value,lam,n*n)-1)//n)*mu%n

def signer_setup():
    kind=CONFIG['sig']
    if kind.startswith('rsa'):
        key=RSA.generate(2048,randfunc=rng('signing-RSA'))
        save_key('client','signing',key.export_key(format='PEM').decode())
        return key.public_key().export_key(format='PEM').decode()
    if kind=='dsa':key=DSA.generate(2048,randfunc=rng('signing-DSA'))
    elif kind=='ecdsa':key=ECC.generate(curve='P-256',randfunc=rng('signing-ECDSA'))
    else:
        p=467 if DEMO_MODE else RFC_P;q=(p-1)//2;g=2 if kind=='elgamal' else 4
        x=127 if DEMO_MODE else secrets.randbelow(q-2)+1
        save_key('client','signing',x);return {'p':p,'g':g,'y':pow(g,x,p)}
    private=key.export_key(format='PEM');public=key.public_key().export_key(format='PEM')
    save_key('client','signing',private.decode() if isinstance(private,bytes) else private)
    return public.decode() if isinstance(public,bytes) else public
def sign(raw):
    kind=CONFIG['sig'];hashed=digest(raw)
    if kind in ('elgamal','schnorr'):
        spec=PUBLIC['sign'];p,g=spec['p'],spec['g'];q=(p-1)//2;x=load_key('client','signing');mod=p-1 if kind=='elgamal' else q
        k=int.from_bytes(rng('signature-'+hashed.hexdigest())(32),'big')%(mod-1)+1
        if kind=='elgamal':
            while math.gcd(k,mod)!=1:k=k%mod+1
        r=pow(g,k,p)
        if kind=='elgamal':return [r,pow(k,-1,mod)*(int.from_bytes(hashed.digest(),'big')-x*r)%mod]
        challenge=int.from_bytes(digest(canonical([r,hashed.hexdigest()])).digest(),'big')%q
        return [r,(k+challenge*x)%q]
    key_raw=load_key('client','signing')
    key=RSA.import_key(key_raw) if kind.startswith('rsa') else DSA.import_key(key_raw) if kind=='dsa' else ECC.import_key(key_raw)
    if kind=='rsa_v15':signature=pkcs1_15.new(key).sign(hashed)
    elif kind=='rsa_pss':signature=pss.new(key,rand_func=rng('pss-'+hashed.hexdigest())).sign(hashed)
    else:signature=DSS.new(key,'fips-186-3',randfunc=rng('dss-'+hashed.hexdigest())).sign(hashed)
    return signature.hex()
def verify_signature(raw,signature):
    kind=CONFIG['sig'];hashed=digest(raw)
    try:
        if kind in ('elgamal','schnorr'):
            spec=PUBLIC['sign'];p,g,y=(spec[k] for k in ('p','g','y'));r,s=signature;mod=p-1 if kind=='elgamal' else (p-1)//2
            if not(0<r<p and 0<=s<mod):return False
            if kind=='elgamal':return pow(g,int.from_bytes(hashed.digest(),'big')%mod,p)==pow(y,r,p)*pow(r,s,p)%p
            e=int.from_bytes(digest(canonical([r,hashed.hexdigest()])).digest(),'big')%mod
            return pow(r,mod,p)==1 and pow(g,s,p)==r*pow(y,e,p)%p
        key_raw=PUBLIC['sign']
        key=RSA.import_key(key_raw) if kind.startswith('rsa') else DSA.import_key(key_raw) if kind=='dsa' else ECC.import_key(key_raw)
        if kind=='rsa_v15':pkcs1_15.new(key).verify(hashed,bytes.fromhex(signature))
        elif kind=='rsa_pss':pss.new(key).verify(hashed,bytes.fromhex(signature))
        else:DSS.new(key,'fips-186-3').verify(hashed,bytes.fromhex(signature))
        return True
    except (ValueError,TypeError,KeyError,IndexError):return False

# RFC 3526 group 14 for REAL ElGamal/Schnorr examples; fixed public modulus.
RFC_P=int('''FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6D
F25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6
F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8
A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356
208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E46
2E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6
955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'''.replace('\n',''),16)

def token(record_id):
    key=bytes.fromhex(load_key('review','index'))
    if CONFIG['index']=='hmac':return hmac.new(key,record_id.encode(),hashlib.sha256).hexdigest()
    return AES.new(key,AES.MODE_SIV).encrypt_and_digest(record_id.encode())[0].hex()

# ================= ZONE 4: CONFIGURATION FLAGS =================
# For the example 500 + 700: MAX_AMOUNT=1000, MAX_SELECTIONS=3, n=3127.
# Keep MAX_SELECTIONS * MAX_AMOUNT < the Paillier modulus in demo mode.
# If you change crypto or a saved setting, save under a fresh .py filename.
DEMO_MODE=True             # False: random inputs/keys and 2048-bit Paillier modulus.
REQUIRE_LOGIN=False        # True: local demonstration passwords on role entry.
MAX_AMOUNT=1000 if DEMO_MODE else 10**9
MAX_SELECTIONS=3 if DEMO_MODE else 100
DATA_DIR=Path(__file__).with_suffix('')  # Separate state folder for each answer.

def store(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_suffix('.tmp')
    tmp.write_bytes(canonical(obj));tmp.replace(path)
def load(path):return json.loads(path.read_bytes())
def save():
    path=DATA_DIR/('records.'+CONFIG['storage'])
    if CONFIG['storage']=='sqlite':
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, blob BLOB)')
            db.execute('INSERT OR REPLACE INTO state VALUES(1,?)',(canonical(STATE),))
    else:store(path,STATE)
def restore():
    path=DATA_DIR/('records.'+CONFIG['storage'])
    if CONFIG['storage']=='sqlite':
        with sqlite3.connect(path) as db:return json.loads(db.execute('SELECT blob FROM state WHERE id=1').fetchone()[0])
    return load(path)
def setup():
    global PUBLIC,STATE
    public=DATA_DIR/'public.json'
    if public.exists():
        PUBLIC=load(public);require(PUBLIC['config']==CONFIG and PUBLIC['demo']==DEMO_MODE,'Saved settings changed; use a new filename/state folder.')
        STATE=restore();return
    DATA_DIR.mkdir(parents=True,exist_ok=True);say('keygen')
    save_key('review','description',payload_key().hex());save_key('review','index',rng('index-key')(32).hex())
    he=he_setup();PUBLIC={'he':he,'sign':None,'config':CONFIG,'demo':DEMO_MODE}
    PUBLIC['sign']=signer_setup();STATE={'records':{},'index':{},'aggregate':None}
    store(public,PUBLIC);save()

# ================= ZONE 5: REQUEST / REVIEW / AGGREGATION ACTIONS =================
# Signed body fields live in record_body(); submit() encrypts the description
# separately from the amount. verified_record() checks hash, signature, index.
# aggregate() combines ciphertexts; finalize() decrypts only the total.
def record_body(record):return {key:record[key] for key in ('id','iv','ct','amount_ct')}
def verified_record(record_id):
    require(record_id in STATE['records'],'Record ID not found.')
    record=STATE['records'][record_id];body=record_body(record);expected=digest(canonical(body)).hexdigest()
    require(hmac.compare_digest(expected,record['hash']),'Record hash mismatch.')
    require(verify_signature(canonical(body),record['signature']),'Invalid digital signature.')
    require(token(record_id) in STATE['index'] and STATE['index'][token(record_id)]==record_id,'Record index tampered.')
    require(0<=record['amount_ct']<PUBLIC['he']['n']**2,'Invalid Paillier ciphertext.')
    return record

def submit():
    permission('submit');record_id=ask('id');description=ask('description');value=int(ask('amount'))
    require(record_id and len(record_id)<=64 and all(c.isalnum() or c in '-_' for c in record_id),'Use a short alphanumeric record ID.')
    require(record_id not in STATE['records'],'Duplicate record ID.')
    require(description and len(description.encode('utf-8'))<=4096,'Description required (<=4096 UTF-8 bytes).')
    require(0<=value<=MAX_AMOUNT,'Amount outside configured range.')
    iv=iv_for(record_id);ct=encrypt_text(description.encode('utf-8'),iv);amount_ct=he_encrypt(value,record_id)
    body=dict(id=record_id,iv=iv.hex(),ct=ct.hex(),amount_ct=amount_ct)
    record={**body,'hash':digest(canonical(body)).hexdigest(),'signature':sign(canonical(body))}
    STATE['records'][record_id]=record;STATE['index'][token(record_id)]=record_id;save()
    say('iv',value=iv.hex() if CIPHER_MODE!='ecb' else 'none (ECB)')
    say('ct',value=ct.hex());say('paillier',value=hex(amount_ct));say('hash',value=record['hash']);say('signature',value=record['signature'])
    say('stored',id=record_id);return record_id

def view():
    permission('view')
    if not STATE['records']:say('empty')
    for id,record in STATE['records'].items():
        say('row',id=id,ct=record['ct'],he=hex(record['amount_ct']),digest=record['hash'])
    return list(STATE['records'])

def verify_action():
    permission('verify');id=ask('id');verified_record(id);say('verified',id=id);return True

def search():
    permission('search');id=ask('id');matched=STATE['index'].get(token(id))
    if matched is None:say('missing',id=id);return None
    verified_record(matched);say('found',id=matched);return matched

def hex_view():
    permission('hex');id=ask('id');record=verified_record(id)
    raw=decrypt_text(bytes.fromhex(record['ct']),bytes.fromhex(record['iv']))
    say('decrypted',value=raw.decode('utf-8'));say('hex_result',value=raw.hex());return raw

def parse_ids(raw):return [part for part in raw.replace(',',' ').split() if part]
def aggregate():
    permission('aggregate');require(STATE['aggregate'] is None,'Finalize the previous aggregate first.')
    ids=parse_ids(ask('ids'));require(2<=len(ids)<=MAX_SELECTIONS and len(ids)==len(set(ids)),'Select 2 or more distinct IDs (within the demo cap).')
    require(len(ids)*MAX_AMOUNT<PUBLIC['he']['n'],'Configured maximum possible sum exceeds Paillier modulus.')
    ciphertexts=[verified_record(id)['amount_ct'] for id in ids]
    combined=math.prod(ciphertexts)%(PUBLIC['he']['n']**2)
    STATE['aggregate']={'ids':ids,'ct':combined};save();say('product',value=hex(combined));return combined

def finalize():
    permission('finalize');require(STATE['aggregate'] is not None,'Aggregate selected records first.')
    current=STATE['aggregate'];n=PUBLIC['he']['n']
    values=[verified_record(id)['amount_ct'] for id in current['ids']]
    require(math.prod(values)%(n*n)==current['ct'],'Aggregate ciphertext modified.')
    total=he_decrypt_aggregate(current['ct']);say('total',value=total);say('private')
    STATE['aggregate']=None;save();return total

# ================= ZONE 6: NESTED EXAM MENUS =================
def menu(name):
    global ROLE
    while True:
        say(name+'_menu' if name!='main' else 'main')
        for i,(_,label) in enumerate(MENUS[name],1):print(i,label)
        try:
            number=int(ask('choice'));require(1<=number<=len(MENUS[name]),'Unknown menu choice.')
            action=MENUS[name][number-1][0]
            if action in ('exit','back'):return
            if name=='main':
                ROLE=action
                try:
                    if REQUIRE_LOGIN:require(input('Local role password: ')==DEMO_PASSWORDS[ROLE],'Invalid login.')
                    menu(action)
                finally:ROLE=None
            else:
                {'submit':submit,'view':view,'verify':verify_action,'search':search,'hex':hex_view,'aggregate':aggregate,'finalize':finalize}[action]()
        except (ValueError,KeyError,TypeError,UnicodeError,OSError) as e:print('Rejected:',e)

def main():
    setup();print(S['title']);say('ready',count=len(STATE['records']),storage=CONFIG['storage'])
    if '--keygen' not in sys.argv:menu('main')
if __name__=='__main__':
    try:main()
    except (EOFError,KeyboardInterrupt):print('Exit')
