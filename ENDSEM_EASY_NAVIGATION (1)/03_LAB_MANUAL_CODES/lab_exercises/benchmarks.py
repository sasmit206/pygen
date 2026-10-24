"""Labs 2/3: timed encryption/decryption with exact round-trip checks.
25 symmetric configurations x five messages; CSV + SVG plotting using stdlib.
RSA2048/P256/ElGamal2048/Rabin2048 hybrid file comparison: asymmetric crypto wraps
an AES256-GCM key, never tries to RSA-encrypt a megabyte in one operation.
Timing results are local observations, not general performance guarantees.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import csv,hashlib,json,secrets,time,html
from pathlib import Path
from Crypto.Cipher import AES,DES,DES3,PKCS1_OAEP
from Crypto.PublicKey import RSA,ECC
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad,unpad
from Crypto.Util.number import getPrime
FAMILIES={'aes128':(AES,16),'aes192':(AES,24),'aes256':(AES,32),'des':(DES,8),'3des':(DES3,24)}
def symmetric(repeats=10):
    rows=[]
    for family,(module,keylen) in FAMILIES.items():
        key=secrets.token_bytes(keylen)
        if family=='3des':key=DES3.adjust_key_parity(key)
        for mode in ('ECB','CBC','CFB','OFB','CTR'):
            size=module.block_size;iv=secrets.token_bytes(size)
            def cipher():
                options={} if mode=='ECB' else {'nonce':b'','initial_value':int.from_bytes(iv,'big')} if mode=='CTR' else {'iv':iv}
                if mode=='CFB':options['segment_size']=size*8
                return module.new(key,getattr(module,'MODE_'+mode),**options)
            for number,raw in enumerate([b'Hello World',b'Information Security',b'Cryptography Lab',b'A'*1024,b'B'*10240],1):
                prepared=pad(raw,size) if mode in ('CBC','ECB') else raw
                t=time.perf_counter()
                for _ in range(repeats):ct=cipher().encrypt(prepared)
                enc=(time.perf_counter()-t)/repeats;t=time.perf_counter()
                for _ in range(repeats):plain=cipher().decrypt(ct)
                dec=(time.perf_counter()-t)/repeats
                assert (unpad(plain,size) if mode in ('CBC','ECB') else plain)==raw
                rows.append(dict(algorithm=family+'_'+mode,message=number,bytes=len(raw),encrypt_seconds=enc,decrypt_seconds=dec))
    return rows

def hybrid(kind,size):
    start=time.perf_counter()
    if kind=='rsa':private=RSA.generate(2048);public=private.public_key()
    elif kind=='ecc':private=ECC.generate(curve='P-256');public=private.public_key()
    elif kind=='elgamal':
        # RFC3526 group14, exactly the prime used by the endsem engine.
        from pathlib import Path
        namespace={};exec((Path(__file__).resolve().parents[1]/'templates/parameters.py.txt').read_text(),namespace)
        p=namespace['RFC_P'];g=2;x=secrets.randbelow(p-3)+2;y=pow(g,x,p)
    elif kind=='rabin':
        def blum():
            while True:
                value=getPrime(1024)
                if value%4==3:return value
        p,q=blum(),blum()
        while q==p:q=blum()
        n=p*q
    else:raise ValueError('Unknown hybrid')
    generation=time.perf_counter()-start;raw=secrets.token_bytes(size);key=secrets.token_bytes(32);start=time.perf_counter()
    if kind=='rsa':wrapped=PKCS1_OAEP.new(public,hashAlgo=SHA256).encrypt(key)
    elif kind=='ecc':
        ephemeral=ECC.generate(curve='P-256');key=hashlib.sha256(int((public.pointQ*ephemeral.d).x).to_bytes(32,'big')).digest()
    elif kind=='elgamal':
        k=secrets.randbelow(p-3)+2;a=pow(g,k,p);b=int.from_bytes(key,'big')*pow(y,k,p)%p
    else:
        frame=b'RB'+key+hashlib.sha256(key).digest()[:16];wrapped=pow(int.from_bytes(frame,'big'),2,n)
    cipher=AES.new(key,AES.MODE_GCM);ct,tag=cipher.encrypt_and_digest(raw);enc=time.perf_counter()-start;start=time.perf_counter()
    if kind=='rsa':recovered=PKCS1_OAEP.new(private,hashAlgo=SHA256).decrypt(wrapped)
    elif kind=='ecc':recovered=hashlib.sha256(int((ephemeral.pointQ*private.d).x).to_bytes(32,'big')).digest()
    elif kind=='elgamal':recovered=(b*pow(pow(a,x,p),-1,p)%p).to_bytes(32,'big')
    else:
        from asymmetric_workbench import roots
        candidates=[]
        for root in roots(wrapped,p,q):
            frame=root.to_bytes((root.bit_length()+7)//8,'big')
            if len(frame)==50 and frame[:2]==b'RB' and frame[-16:]==hashlib.sha256(frame[2:34]).digest()[:16]:candidates.append(frame[2:34])
        assert len(candidates)==1;recovered=candidates[0]
    plain=AES.new(recovered,AES.MODE_GCM,nonce=cipher.nonce).decrypt_and_verify(ct,tag);assert plain==raw
    return dict(algorithm=kind+'_AES256_GCM',message=1,bytes=size,encrypt_seconds=enc,decrypt_seconds=time.perf_counter()-start,keygen_seconds=generation)

def save(rows,prefix):
    prefix=Path(prefix);fields=list(rows[0])
    with prefix.with_suffix('.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
    groups={}
    for row in rows:groups.setdefault(row['algorithm'],[]).append(row['encrypt_seconds']+row['decrypt_seconds'])
    means={key:sum(values)/len(values) for key,values in groups.items()};maximum=max(means.values());parts=['<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="'+str(70+28*len(means))+'"><rect width="100%" height="100%" fill="white"/><text x="15" y="25">Mean encryption + decryption time (seconds; local benchmark)</text>']
    for i,(name,value) in enumerate(means.items()):
        y=50+28*i;parts.append(f'<text x="15" y="{y+15}">{html.escape(name)}</text><rect x="260" y="{y}" width="{600*value/maximum:.2f}" height="20" fill="#2864a5"/><text x="875" y="{y+15}">{value:.6f}</text>')
    prefix.with_suffix('.svg').write_text(''.join(parts)+'</svg>');print('Saved',prefix.with_suffix('.csv'),'and SVG')

def main():
    while True:
        print('\n1 Symmetric: 25 configurations x five messages\n2 RSA/ECC file hybrid (1KB,10KB,1MB,10MB)\n3 RSA/ElGamal/ECC/Rabin hybrid (1KB,10KB)\n4 Exit')
        try:
            c=input('Input Choice: ')
            if c=='4':return
            if c=='1':save(symmetric(),'symmetric_benchmark')
            elif c in ('2','3'):
                kinds=('rsa','ecc') if c=='2' else ('rsa','elgamal','ecc','rabin');sizes=(1024,10240,1048576,10485760) if c=='2' else (1024,10240)
                rows=[]
                for kind in kinds:
                    for size in sizes:row=hybrid(kind,size);rows.append(row);print(row)
                save(rows,'file_benchmark' if c=='2' else 'asymmetric_benchmark')
            else:print('Invalid choice.')
        except (ValueError,OSError) as e:print('Rejected:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
