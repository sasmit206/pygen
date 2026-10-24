"""Labs 3/4: textbook RSA, ElGamal, Rabin/CRT, P256 ECIES-style hybrid,
actual EC-ElGamal byte-point encryption, and DH agreement. Fixed tiny parameters
are for explaining arithmetic only. Large messages require hybrid encryption.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import hashlib,math,secrets
from Crypto.PublicKey import ECC,RSA
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime

def rsa_text(text):
    n,e,d=323,5,173;raw=text.encode();ct=[pow(b,e,n) for b in raw];recovered=bytes(pow(c,d,n) for c in ct)
    assert recovered==raw;return ct,recovered.decode()
def elgamal_text(text):
    p,g,x=7919,2,2999;y=pow(g,x,p)
    # The manual's supplied h is checked rather than trusted blindly.
    result=[]
    for b in text.encode():
        k=secrets.randbelow(p-3)+2;result.append((pow(g,k,p),b*pow(y,k,p)%p))
    raw=bytes(b*pow(pow(a,x,p),-1,p)%p for a,b in result)
    assert raw.decode()==text;return {'computed_h':y,'manual_h':6465,'manual_key_consistent':y==6465,'ciphertexts':result,'plaintext':raw.decode()}
def roots(c,p,q):
    n=p*q;a=pow(c,(p+1)//4,p);b=pow(c,(q+1)//4,q)
    x=(a*q*pow(q,-1,p)+b*p*pow(p,-1,q))%n;y=(a*q*pow(q,-1,p)-b*p*pow(p,-1,q))%n
    return sorted(set([x,(-x)%n,y,(-y)%n]))
def rabin_demo(value=42):
    p,q=499,547;n=p*q
    if not 0<=value<n:raise ValueError('Value outside modulus.')
    ct=pow(value,2,n);candidates=roots(ct,p,q);assert value in candidates
    return {'ciphertext':ct,'four_possible_roots':candidates,'original':value,'note':'Without redundancy there is no unique decryption.'}
def ecc_hybrid(text):
    receiver=ECC.generate(curve='P-256');sender=ECC.generate(curve='P-256')
    a=int((receiver.pointQ*sender.d).x);b=int((sender.pointQ*receiver.d).x);assert a==b
    key=hashlib.sha256(a.to_bytes(32,'big')).digest();cipher=AES.new(key,AES.MODE_GCM)
    ct,tag=cipher.encrypt_and_digest(text.encode());plain=AES.new(key,AES.MODE_GCM,nonce=cipher.nonce).decrypt_and_verify(ct,tag)
    return {'ephemeral_public_key':sender.public_key().export_key(format='PEM'),'ciphertext':ct.hex(),'plaintext':plain.decode()}
def ec_elgamal(text):
    receiver=ECC.generate(curve='P-256');G=ECC.construct(curve='P-256',d=1).pointQ;table={(int((G*i).x),int((G*i).y)):i-1 for i in range(1,257)};ct=[];out=[]
    for value in text.encode():
        k=ECC.generate(curve='P-256');first=k.pointQ;second=G*(value+1)+receiver.pointQ*k.d;ct.append([[int(first.x),int(first.y)],[int(second.x),int(second.y)]])
        recovered=second+-(first*receiver.d);out.append(table[(int(recovered.x),int(recovered.y))])
    return {'ciphertexts':ct,'plaintext':bytes(out).decode()}
def dh_demo():
    p,g,a,b=7919,2,127,71;A,B=pow(g,a,p),pow(g,b,p);first=pow(B,a,p);second=pow(A,b,p)
    assert first==second;return {'publics':[A,B],'shared_demo_secret':first,'derived_AES256_key':hashlib.sha256(str(first).encode()).hexdigest(),'note':'DH establishes a key. It is not a digital signature and alone does not authenticate peers.'}
def main():
    while True:
        print('\n1 Textbook RSA\n2 ElGamal\n3 Rabin four roots\n4 P256 hybrid\n5 EC-ElGamal\n6 DH\n7 Exit')
        try:
            c=input('Input Choice: ')
            if c=='7':return
            if c=='3':print(rabin_demo(int(input('Integer: '))))
            elif c=='6':print(dh_demo())
            elif c in ('1','2','4','5'):print({'1':rsa_text,'2':elgamal_text,'4':ecc_hybrid,'5':ec_elgamal}[c](input('Message: ')))
            else:print('Invalid choice.')
        except ValueError as e:print('Rejected:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
