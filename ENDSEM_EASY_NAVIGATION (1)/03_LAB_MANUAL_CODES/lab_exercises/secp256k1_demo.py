"""Lab 3's named secp256k1 curve: pure-Python ECDH and ECDSA/SHA256 arithmetic.
Educational, variable-time scalar multiplication; never production private keys.
Curve parameters: SEC 2 v2 section 2.4.1. No claim that k1 is supported by Crypto.ECC.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import hashlib,secrets
P=2**256-2**32-977;A=0;B=7
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(first,second):
    if first is None:return second
    if second is None:return first
    x,y=first;u,v=second
    if x==u and (y+v)%P==0:return None
    slope=((3*x*x+A)*pow(2*y,-1,P) if first==second else (v-y)*pow(u-x,-1,P))%P
    w=(slope*slope-x-u)%P;return w,(slope*(x-w)-y)%P

def mul(k,point=G):
    out=None
    while k:
        if k&1:out=add(out,point)
        point=add(point,point);k>>=1
    return out

def valid_point(point):return point is not None and 0<=point[0]<P and 0<=point[1]<P and (point[1]**2-point[0]**3-7)%P==0

def sign(text,private):
    z=int.from_bytes(hashlib.sha256(text.encode()).digest(),'big')
    while True:
        k=secrets.randbelow(N-1)+1;r=mul(k)[0]%N;s=pow(k,-1,N)*(z+r*private)%N
        if r and s:return r,s

def verify(text,pair,public):
    r,s=pair
    if not valid_point(public) or not (0<r<N and 0<s<N):return False
    z=int.from_bytes(hashlib.sha256(text.encode()).digest(),'big');w=pow(s,-1,N);point=add(mul(z*w%N),mul(r*w%N,public));return point is not None and point[0]%N==r

def demo(text='lab'):
    a,b=secrets.randbelow(N-1)+1,secrets.randbelow(N-1)+1;A1,B1=mul(a),mul(b)
    assert mul(a,B1)==mul(b,A1);pair=sign(text,a);assert verify(text,pair,A1) and not verify(text+'!',pair,A1)
    return {'ECDH_shared_point_equal':True,'ECDSA_signature':pair,'signature_valid':True,'tamper_rejected':True}

def self_test():
    assert valid_point(G) and mul(N) is None
    assert mul(2)==(0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A)
    for text in ('lab','message',''):demo(text)
    return True

def main():
    while True:
        print('\n1 ECDH and ECDSA demonstration\n2 Self-test\n3 Exit')
        try:
            c=input('Input Choice: ')
            if c=='3':return
            if c=='1':print(demo(input('Message: ')))
            elif c=='2':print('PASS',self_test())
            else:print('Invalid choice.')
        except (ValueError,TypeError) as e:print('Rejected:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
