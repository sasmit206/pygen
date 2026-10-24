"""BGN teaching implementation with an actual reduced Tate pairing, SMALL insecure
parameters. Lab 8 p.9 names BGN; it is public-key homomorphic encryption, not a
symmetric searchable-index construction. Supports additions and ONE multiplication.
Curve y^2=x^3+x over F_p; p=4*k*N-1 prime, N=11*13; embedding degree 2.
The private factor 11 removes the order-11 noise subgroup. Values wrap modulo 13.
Reference: Boneh, Goh, Nissim, Evaluating 2-DNF Formulas on Ciphertexts (TCC 2005).
No production security, constant-time behavior, or large-message claim.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import secrets
P,N,SECRET,PLAIN_MOD=571,143,11,13
ONE=(1,0)
def add(a,b):return ((a[0]+b[0])%P,(a[1]+b[1])%P)
def neg(a):return (-a[0]%P,-a[1]%P)
def sub(a,b):return add(a,neg(b))
def mul(a,b):return ((a[0]*b[0]-a[1]*b[1])%P,(a[0]*b[1]+a[1]*b[0])%P)
def inv(a):
    d=pow((a[0]*a[0]+a[1]*a[1])%P,-1,P);return (a[0]*d%P,-a[1]*d%P)
def power(a,k):
    result=ONE
    while k:
        if k&1:result=mul(result,a)
        a=mul(a,a);k>>=1
    return result
def point_add(a,b):
    if a is None:return b
    if b is None:return a
    x,y=a;u,v=b
    if x==u and (y+v)%P==0:return None
    slope=((3*x*x+1)*pow(2*y,-1,P) if a==b else (v-y)*pow(u-x,-1,P))%P
    w=(slope*slope-x-u)%P;return (w,(slope*(x-w)-y)%P)
def scalar(a,k):
    out=None
    while k:
        if k&1:out=point_add(out,a)
        a=point_add(a,a);k>>=1
    return out
def generator():
    for x in range(P):
        rhs=(x*x*x+x)%P;y=pow(rhs,(P+1)//4,P)
        if y*y%P!=rhs:continue
        g=scalar((x,y),4)
        if g is not None and scalar(g,N) is None and scalar(g,11) is not None and scalar(g,13) is not None:return g
    raise ValueError('No full-order point found.')
G=generator();H=scalar(G,13)
def line(a,b,q):
    if a is None or b is None:return ONE
    x,y=a;u,v=b
    if x==u and (y+v)%P==0:return sub(q[0],(x,0))
    slope=((3*x*x+1)*pow(2*y,-1,P) if a==b else (v-y)*pow(u-x,-1,P))%P
    r=point_add(a,b);numerator=sub(sub(q[1],(y,0)),mul((slope,0),sub(q[0],(x,0))))
    return numerator if r is None else mul(numerator,inv(sub(q[0],(r[0],0))))
def pairing(a,b):
    if a is None or b is None:return ONE
    # Distortion map sends (x,y) to (-x,i*y) in F_p^2.
    q=((-b[0]%P,0),(0,b[1]));t=a;f=ONE
    for bit in bin(N)[3:]:
        f=mul(mul(f,f),line(t,t,q));t=point_add(t,t)
        if bit=='1':f=mul(f,line(t,a,q));t=point_add(t,a)
    return power(f,(P*P-1)//N)
GT=pairing(G,G)
def encrypt(value,randomizer=None):
    if not 0<=value<PLAIN_MOD:raise ValueError('Toy plaintext must be 0..12.')
    r=secrets.randbelow(N) if randomizer is None else randomizer
    return ('point',point_add(scalar(G,value),scalar(H,r)))
def hom_add(a,b):
    if a[0]!=b[0]:raise ValueError('Add only ciphertexts in the same group.')
    return (a[0],point_add(a[1],b[1]) if a[0]=='point' else mul(a[1],b[1]))
def hom_multiply(a,b):
    if a[0]!='point' or b[0]!='point':raise ValueError('BGN supports only one multiplication level.')
    return ('target',pairing(a[1],b[1]))
def decrypt(c):
    if c[0]=='point':
        target=scalar(c[1],SECRET);base=scalar(G,SECRET);lookup={scalar(base,i):i for i in range(PLAIN_MOD)}
    else:
        target=power(c[1],SECRET);base=power(GT,SECRET);lookup={power(base,i):i for i in range(PLAIN_MOD)}
    return lookup[target]
def self_test():
    assert GT!=ONE and power(GT,N)==ONE and power(GT,SECRET)!=ONE
    assert pairing(scalar(G,2),scalar(G,3))==power(GT,6)
    for x in range(13):
        for y in range(13):
            a,b=encrypt(x,7),encrypt(y,19)
            assert decrypt(a)==x
            assert decrypt(hom_add(a,b))==(x+y)%13
            assert decrypt(hom_multiply(a,b))==x*y%13
    return True
def main():
    while True:
        print('\nBGN: SMALL pairing demo; plaintext arithmetic modulo 13\n1 Add/multiply two values\n2 All 169 pair tests\n3 Exit')
        try:
            c=input('Input Choice: ')
            if c=='3':return
            if c=='2':print('Output checks:',self_test());continue
            if c!='1':print('Invalid choice.');continue
            a,b=encrypt(int(input('First value (0-12): '))),encrypt(int(input('Second value (0-12): ')))
            print('Output ciphertexts:',a,b)
            for label,ct in [('sum',hom_add(a,b)),('product',hom_multiply(a,b))]:print('Output',label,'ciphertext:',ct,'decrypted:',decrypt(ct))
        except (ValueError,KeyError) as e:print('Rejected:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
