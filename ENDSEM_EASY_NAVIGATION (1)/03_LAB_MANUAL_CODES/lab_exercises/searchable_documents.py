"""Lab 8: ten encrypted documents and encrypted inverted indexes.
SSE: HMAC equality or deterministic AES-SIV tokens; AES-GCM encrypted postings.
RSA scan: owner decrypts encrypted keyword hashes to compare with encrypted query.
Paillier scan: owner decrypts encrypted (indexed hash - query hash) and tests zero.
RSA/Paillier scans need the private key; they are NOT server-side PEKS/trapdoors.
Randomized OAEP/Paillier ciphertexts are never matched using ciphertext equality.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import hashlib,hmac,json,math,secrets,re
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime
DOCUMENTS={1:'cryptography protects confidential records',2:'voting uses encrypted ballots and signatures',3:'paillier supports encrypted addition',4:'elgamal supports encrypted multiplication',5:'hashing detects accidental data changes',6:'digital signatures authenticate messages',7:'rsa and ecc support hybrid encryption',8:'searchable encryption uses an encrypted index',9:'voting records support constituency search',10:'secure key management includes rotation and revocation'}

def words(text):return set(re.findall(r'[a-z0-9]+',text.lower()))
def aes_encrypt(key,raw):
    c=AES.new(key,AES.MODE_GCM);ct,tag=c.encrypt_and_digest(raw);return [c.nonce.hex(),ct.hex(),tag.hex()]
def aes_decrypt(key,packet):return AES.new(key,AES.MODE_GCM,nonce=bytes.fromhex(packet[0])).decrypt_and_verify(bytes.fromhex(packet[1]),bytes.fromhex(packet[2]))
def paillier_keys():
    while True:
        p,q=getPrime(256),getPrime(256);n=p*q;lam=math.lcm(p-1,q-1)
        if p!=q and math.gcd(n,lam)==1:return n,lam,pow(lam,-1,n)
def p_enc(value,n):
    if not 0<=value<n:raise ValueError('Message exceeds Paillier modulus.')
    r=secrets.randbelow(n-1)+1
    while math.gcd(r,n)!=1:r=secrets.randbelow(n-1)+1
    return pow(n+1,value,n*n)*pow(r,n,n*n)%(n*n)
def p_dec(ct,private):
    n,lam,mu=private;return ((pow(ct,lam,n*n)-1)//n)*mu%n
class Collection:
    def __init__(self,mode):
        if mode not in ['sse_hmac','sse_aes','rsa_scan','paillier_scan']:raise ValueError('Unknown search mode.')
        self.mode=mode;self.key=secrets.token_bytes(32);self.rsa=RSA.generate(2048) if mode=='rsa_scan' else None;self.phe=paillier_keys() if mode=='paillier_scan' else None
        inverted={}
        for ident,text in DOCUMENTS.items():
            for word in words(text):inverted.setdefault(word,[]).append(ident)
        self.documents={i:aes_encrypt(self.key,t.encode()) for i,t in DOCUMENTS.items()};self.index={}
        for word,ids in inverted.items():
            token=self.query(word)
            if mode=='rsa_scan':postings=[PKCS1_OAEP.new(self.rsa.public_key(),hashAlgo=SHA256).encrypt(str(i).encode()).hex() for i in ids]
            elif mode=='paillier_scan':postings=[p_enc(i,self.phe[0]) for i in ids]
            else:postings=aes_encrypt(self.key,json.dumps(ids).encode())
            self.index[str(token)]=postings
    def query(self,word):
        normalized=word.lower().strip().encode()
        if self.mode=='sse_hmac':return hmac.new(self.key,normalized,hashlib.sha256).hexdigest()
        if self.mode=='sse_aes':
            c=AES.new(hashlib.sha512(self.key).digest(),AES.MODE_SIV);ct,tag=c.encrypt_and_digest(normalized);return (tag+ct).hex()
        hashed=hashlib.sha256(normalized).digest()
        if self.mode=='rsa_scan':return PKCS1_OAEP.new(self.rsa.public_key(),hashAlgo=SHA256).encrypt(hashed).hex()
        return p_enc(int.from_bytes(hashed,'big'),self.phe[0])
    def search(self,word):
        query=self.query(word);ids=[]
        if self.mode.startswith('sse'):
            packet=self.index.get(query)
            if packet:ids=json.loads(aes_decrypt(self.key,packet))
        else:
            if self.mode=='rsa_scan':query_hash=PKCS1_OAEP.new(self.rsa,hashAlgo=SHA256).decrypt(bytes.fromhex(query))
            for token,postings in self.index.items():
                if self.mode=='rsa_scan':
                    matched=hmac.compare_digest(PKCS1_OAEP.new(self.rsa,hashAlgo=SHA256).decrypt(bytes.fromhex(token)),query_hash)
                    if matched:ids.extend(int(PKCS1_OAEP.new(self.rsa,hashAlgo=SHA256).decrypt(bytes.fromhex(i))) for i in postings)
                else:
                    n=self.phe[0];difference=int(token)*pow(query,-1,n*n)%(n*n)
                    if p_dec(difference,self.phe)==0:ids.extend(p_dec(i,self.phe) for i in postings)
        return {i:aes_decrypt(self.key,self.documents[i]).decode() for i in sorted(set(ids))}
def self_test():
    rows=[]
    for mode in ['sse_hmac','sse_aes','rsa_scan','paillier_scan']:
        db=Collection(mode);assert sorted(db.search('voting'))==[2,9];assert sorted(db.search('encrypted'))==[2,3,4,8];assert db.search('nonexistent')=={}
        raw=json.dumps(db.index).encode();assert b'cryptography' not in raw and b'voting' not in raw
        if not mode.startswith('sse'):assert db.query('voting')!=db.query('voting')
        packet=db.documents[1][:];ct=bytearray.fromhex(packet[1]);ct[0]^=1;packet[1]=ct.hex()
        try:aes_decrypt(db.key,packet);raise AssertionError('Tampered document accepted')
        except ValueError:pass
        rows.append(mode+' PASS')
    return rows

def main():
    collection=None
    while True:
        print('\n1 Build encrypted corpus\n2 Search\n3 View encrypted index\n4 Run checks\n5 Exit')
        try:
            c=input('Input Choice: ')
            if c=='5':return
            if c=='1':collection=Collection(input('Mode (sse_hmac/sse_aes/rsa_scan/paillier_scan): '));print('Output encrypted documents:',len(collection.documents))
            elif c=='2':
                if collection is None:raise ValueError('Build a corpus first.')
                print('Output matches:',collection.search(input('Keyword: ')))
            elif c=='3':
                if collection is None:raise ValueError('Build a corpus first.')
                print(collection.index)
            elif c=='4':print(self_test())
            else:print('Invalid choice.')
        except (ValueError,KeyError) as e:print('Rejected:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
