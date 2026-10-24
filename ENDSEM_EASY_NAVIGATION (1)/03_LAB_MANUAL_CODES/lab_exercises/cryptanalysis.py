"""Lab 1 known-plaintext, chosen-plaintext and exhaustive toy-cipher attacks;
Lab 4 RSA weak-prime demonstration. Runs only on built-in educational examples.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import math

def affine_decrypt(text,a,b):
    inv=pow(a,-1,26);return ''.join(chr((inv*(ord(c)-65-b))%26+65) if 'A'<=c<='Z' else c for c in text.upper())
def caesar_attack():
    # Known plaintext YES -> CIW determines shift 4.
    shift=(ord('C')-ord('Y'))%26;plain=affine_decrypt('XVIEWYWI',1,shift)
    print('Known-plaintext attack: key =',shift,'recovered =',plain);assert plain=='TREASUSE';print('Manual ciphertext decrypts literally to TREASUSE. TREASURE would require XVIEWYVI.');return plain

def affine_attack():
    # AB -> GL: b=6, a=(11-6)=5. Exhaustive search confirms the known-pair constraint.
    candidates=[]
    for a in range(26):
        if math.gcd(a,26)!=1:continue
        for b in range(26):
            if b==6 and (a+b)%26==11:candidates.append((a,b,affine_decrypt('XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS',a,b)))
    print('Affine candidates:',candidates);assert len(candidates)==1;return candidates

def brute_shift():
    text='NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY'
    return [(key,affine_decrypt(text,1,key)) for key in range(26)]
def recover_permutation(plain,cipher):
    if sorted(plain)!=sorted(cipher):raise ValueError('Not a pure transposition: output contains a symbol absent from input. The manual ABCDEFGHI -> CABDEHFGL example has I/L inconsistency.')
    return [plain.index(c) for c in cipher]
def weak_rsa():
    n,e=323,5;p=next(x for x in range(2,math.isqrt(n)+1) if n%x==0);q=n//p
    d=pow(e,-1,(p-1)*(q-1));ct=pow(65,e,n);plain=pow(ct,d,n)
    print('Toy factorization:',p,q,'recovered d:',d,'plaintext:',plain)
    print('Mitigation: independent large random primes and vetted RSA-OAEP/signature schemes.')
    assert plain==65;return d

def main():
    while True:
        print('\n1 Known-plaintext shift\n2 Affine exhaustive search\n3 All shift keys\n4 Chosen-plaintext permutation\n5 Weak RSA\n6 Exit')
        try:
            choice=input('Input Choice: ')
            if choice=='6':return
            if choice=='1':caesar_attack()
            elif choice=='2':affine_attack()
            elif choice=='3':
                for key,plain in brute_shift():print(key,plain)
            elif choice=='4':print(recover_permutation(input('Distinct-symbol input: '),input('Output: ')))
            elif choice=='5':weak_rsa()
            else:print('Invalid choice.')
        except (ValueError,StopIteration) as e:print(e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
