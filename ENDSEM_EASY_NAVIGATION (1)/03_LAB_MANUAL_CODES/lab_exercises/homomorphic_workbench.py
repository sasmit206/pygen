"""Lab 7: Paillier addition, textbook RSA/ElGamal multiplication, scalar
multiplication and toy timing. All arithmetic is exact modulo the plaintext space.
Small fixed primes are for hand-checkable lab work only. No encrypted comparison.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import math,secrets,time
P,Q=53,59;N=P*Q;G=N+1;LAM=math.lcm(P-1,Q-1);MU=pow(LAM,-1,N)
def paillier(m):
    if not 0<=m<N:raise ValueError('Paillier plaintext must be in 0..3126.')
    while True:
        r=secrets.randbelow(N-1)+1
        if math.gcd(r,N)==1:return pow(G,m,N*N)*pow(r,N,N*N)%(N*N)
def paillier_open(c):return ((pow(c,LAM,N*N)-1)//N)*MU%N

def demo(a=15,b=25):
    ca,cb=paillier(a),paillier(b);combined=ca*cb%(N*N);total=paillier_open(combined);assert total==(a+b)%N
    return dict(first=hex(ca),second=hex(cb),aggregate=hex(combined),decrypted_sum=total,expected=(a+b)%N)
def multiplicative(kind,a=7,b=3):
    if kind=='rsa':
        n,e,d=323,5,173
        if not 0<=a<n or not 0<=b<n:raise ValueError('RSA values must be in 0..322.')
        c1,c2=pow(a,e,n),pow(b,e,n);ct=c1*c2%n;result=pow(ct,d,n);modulus=n
    else:
        p,g,x=467,2,127;y=pow(g,x,p)
        if not 1<=a<p or not 1<=b<p:raise ValueError('ElGamal values must be in 1..466.')
        def enc(m):
            k=secrets.randbelow(p-2)+1;return pow(g,k,p),m*pow(y,k,p)%p
        c1,c2=enc(a),enc(b);ct=(c1[0]*c2[0]%p,c1[1]*c2[1]%p);result=ct[1]*pow(pow(ct[0],x,p),-1,p)%p;modulus=p
    assert result==a*b%modulus;return dict(first=c1,second=c2,aggregate=ct,decrypted_product=result,expected=a*b%modulus)

def scalar(m,k):
    if k<0:raise ValueError('Use a nonnegative multiplier.')
    c=paillier(m);result=paillier_open(pow(c,k,N*N));assert result==m*k%N;return result

def benchmark(repeats=100):
    rows=[]
    for name,fn in [('Paillier sum',demo),('RSA product',lambda:multiplicative('rsa')),('ElGamal product',lambda:multiplicative('elgamal'))]:
        start=time.perf_counter()
        for _ in range(repeats):fn()
        rows.append(dict(operation=name,average_seconds=(time.perf_counter()-start)/repeats))
    return rows

def self_test():
    assert demo()['decrypted_sum']==40
    assert multiplicative('rsa')['decrypted_product']==21 and multiplicative('elgamal')['decrypted_product']==21
    assert scalar(15,3)==45 and demo(N-1,1)['decrypted_sum']==0
    return benchmark(10)

def main():
    while True:
        print('\n1 Paillier addition\n2 RSA multiplication\n3 ElGamal multiplication\n4 Paillier scalar multiplication\n5 Benchmark\n6 Exit')
        try:
            c=input('Input Choice: ')
            if c=='6':return
            if c=='5':print(benchmark())
            elif c in ('1','2','3','4'):
                a=int(input('First value: '));b=int(input('Second value / scalar: '))
                print(demo(a,b) if c=='1' else scalar(a,b) if c=='4' else multiplicative('rsa' if c=='2' else 'elgamal',a,b))
            else:print('Invalid choice.')
        except ValueError as e:print('Rejected:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
