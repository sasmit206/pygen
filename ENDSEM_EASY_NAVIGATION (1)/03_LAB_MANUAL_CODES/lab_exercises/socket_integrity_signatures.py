"""Labs 5/6: real TCP, multipart reassembly, hash return/comparison, ElGamal,
Schnorr and RSA signatures, RSA+AES confidentiality, and DH key agreement.
All connections default to loopback. Fixed demo signing keys are prearranged in
this source; they are NOT secret/production credentials. Bare DH is unauthenticated.
Menu 1 runs both peers locally; menu 2/3 can run in separate terminals.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import socket,threading,struct,json,hashlib,hmac,secrets,functools
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def deterministic(label):
    counter=0
    def take(n):
        nonlocal counter
        data=b''
        while len(data)<n:data+=hashlib.sha256((label+str(counter)).encode()).digest();counter+=1
        return data[:n]
    return take
@functools.lru_cache(None)
def key(owner):return RSA.generate(2048,randfunc=deterministic(owner))
def hashed(raw,name):
    if name=='djb2':
        value=5381
        for b in raw:value=((value<<5)+value+b)&0xffffffff
        return f'{value:08x}'
    return hashlib.new(name,raw).hexdigest()
def signature(raw,kind):
    if kind=='rsa':return pkcs1_15.new(key('client')).sign(SHA256.new(raw)).hex()
    p,x,k=467,127,53;g=4 if kind=='schnorr' else 2;r=pow(g,k,p)
    if kind=='elgamal':return [r,pow(k,-1,p-1)*(int.from_bytes(hashlib.sha512(raw).digest(),'big')-x*r)%(p-1)]
    e=int.from_bytes(hashlib.sha256(str(r).encode()+b'|'+raw).digest(),'big')%233;return [r,(k+e*x)%233]
def verify(raw,sig,kind):
    if kind=='rsa':
        try:pkcs1_15.new(key('client').public_key()).verify(SHA256.new(raw),bytes.fromhex(sig));return True
        except (ValueError,TypeError):return False
    r,s=sig;p=467;g=4 if kind=='schnorr' else 2;y=pow(g,127,p)
    if not 0<r<p:return False
    if kind=='elgamal':return 0<=s<p-1 and pow(g,int.from_bytes(hashlib.sha512(raw).digest(),'big')%(p-1),p)==pow(y,r,p)*pow(r,s,p)%p
    e=int.from_bytes(hashlib.sha256(str(r).encode()+b'|'+raw).digest(),'big')%233
    return 0<=s<233 and pow(g,s,p)==r*pow(y,e,p)%p

def exact(sock,n):
    data=b''
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part:raise ValueError('Truncated TCP frame.')
        data+=part
    return data
def send(sock,value):
    raw=json.dumps(value,separators=(',',':')).encode();sock.sendall(struct.pack('!I',len(raw))+raw)
def receive(sock):
    length=struct.unpack('!I',exact(sock,4))[0]
    if length>2*1024*1024:raise ValueError('Frame too large.')
    return json.loads(exact(sock,length))
def handle(sock):
    packet=receive(sock);kind=packet['kind']
    if kind=='dh':
        p,g=7919,2;b=secrets.randbelow(p-3)+2;A=packet['A']
        if not 1<A<p-1:raise ValueError('Invalid DH public value.')
        B=pow(g,b,p);shared=pow(A,b,p);derived=hashlib.sha256(str(shared).encode()).digest()
        send(sock,{'B':B,'confirmation':hmac.new(derived,b'server-confirmation',hashlib.sha256).hexdigest()});return
    if not 0<=packet['count']<=1000:raise ValueError('Invalid part count.')
    raw=b''.join(bytes.fromhex(receive(sock)['part']) for _ in range(packet['count']))
    if kind=='secure':
        payload_key=PKCS1_OAEP.new(key('server'),hashAlgo=SHA256).decrypt(bytes.fromhex(packet['wrapped']))
        raw=AES.new(payload_key,AES.MODE_GCM,nonce=bytes.fromhex(packet['nonce'])).decrypt_and_verify(raw,bytes.fromhex(packet['tag']))
    valid=verify(raw,packet['signature'],packet['signature_kind']) if kind in ('signature','secure') else None
    send(sock,{'hash':hashed(raw,packet['hash_name']),'signature_valid':valid,'parts_received':packet['count']})
def server(listener,count=1):
    for _ in range(count):
        conn,_=listener.accept()
        with conn:
            conn.settimeout(15)
            try:handle(conn)
            except (ValueError,KeyError,TypeError,OSError) as e:send(conn,{'error':str(e)})
def client(port,kind='hash',text='Information Security Lab',hash_name='sha256',signature_kind='rsa',tamper=False):
    raw=text.encode();packet={'kind':kind,'hash_name':hash_name,'signature_kind':signature_kind};original=raw
    with socket.create_connection(('127.0.0.1',port),timeout=15) as sock:
        if kind=='dh':
            p,g=7919,2;a=secrets.randbelow(p-3)+2;send(sock,{'kind':'dh','A':pow(g,a,p)});response=receive(sock)
            shared=pow(response['B'],a,p);derived=hashlib.sha256(str(shared).encode()).digest()
            return {'DH_shared_key_confirmed':hmac.compare_digest(response['confirmation'],hmac.new(derived,b'server-confirmation',hashlib.sha256).hexdigest())}
        if kind in ('signature','secure'):packet['signature']=signature(raw,signature_kind)
        if kind=='secure':
            payload_key=secrets.token_bytes(32);cipher=AES.new(payload_key,AES.MODE_GCM);raw,tag=cipher.encrypt_and_digest(raw)
            packet.update(wrapped=PKCS1_OAEP.new(key('server').public_key(),hashAlgo=SHA256).encrypt(payload_key).hex(),nonce=cipher.nonce.hex(),tag=tag.hex())
        if tamper and raw:raw=bytes([raw[0]^1])+raw[1:]
        parts=[raw[i:i+7] for i in range(0,len(raw),7)];packet['count']=len(parts);send(sock,packet)
        for part in parts:send(sock,{'part':part.hex()})
        result=receive(sock)
        result['integrity_match']=result.get('hash')==hashed(original,hash_name);return result

def local_demo():
    cases=[('hash','sha256','rsa',False),('hash','sha256','rsa',True),('hash','djb2','rsa',False),('signature','sha256','rsa',False),('signature','sha256','elgamal',False),('signature','sha256','schnorr',False),('signature','sha256','rsa',True),('secure','sha256','rsa',False),('secure','sha256','rsa',True),('dh','sha256','rsa',False)]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen();port=listener.getsockname()[1]
        thread=threading.Thread(target=server,args=(listener,len(cases)),daemon=True);thread.start();result=[]
        for kind,hash_name,sig,tamper in cases:
            row=client(port,kind,hash_name=hash_name,signature_kind=sig,tamper=tamper)
            if kind=='dh':assert row['DH_shared_key_confirmed']
            else:assert row['integrity_match']==(not tamper),(kind,row)
            if kind=='signature':assert row['signature_valid']==(not tamper)
            result.append({'case':[kind,hash_name,sig,tamper],'result':row})
        thread.join(20);assert not thread.is_alive();return result

def main():
    while True:
        print('\n1 Run both peers and tamper tests\n2 Run one-request server (127.0.0.1:9099)\n3 Run client\n4 Exit')
        try:
            choice=input('Input Choice: ')
            if choice=='4':return
            if choice=='1':
                for row in local_demo():print(row)
            elif choice=='2':
                with socket.socket() as listener:listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',9099));listener.listen();print('Waiting for client...');server(listener)
            elif choice=='3':print(client(9099,input('Kind (hash/signature/secure/dh): '),input('Message: ')))
            else:print('Invalid choice.')
        except (ValueError,OSError,KeyError) as e:print('Error:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
