"""Lab 2: actual AES key expansion and every encryption round, all key lengths.
Independent educational implementation verified against PyCryptodome AES-ECB.
AES operates on 16-byte blocks; a message demonstration uses PKCS7 padding.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def mul(a,b):
    out=0
    while b:
        if b&1:out^=a
        a=((a<<1)^ (0x11b if a&0x80 else 0))&255;b>>=1
    return out
def power(a,n):
    out=1
    while n:
        if n&1:out=mul(out,a)
        a=mul(a,a);n>>=1
    return out
def substitute(x):
    x=power(x,254) if x else 0
    return x^((x<<1|x>>7)&255)^((x<<2|x>>6)&255)^((x<<3|x>>5)&255)^((x<<4|x>>4)&255)^0x63
SBOX=[substitute(x) for x in range(256)]
def expand(key):
    if len(key) not in (16,24,32):raise ValueError('AES requires 16, 24 or 32 key bytes.')
    nk=len(key)//4;rounds=nk+6;words=[list(key[i:i+4]) for i in range(0,len(key),4)];rc=1
    for i in range(nk,4*(rounds+1)):
        temp=words[-1][:]
        if i%nk==0:temp=[SBOX[x] for x in temp[1:]+temp[:1]];temp[0]^=rc;rc=mul(rc,2)
        elif nk>6 and i%nk==4:temp=[SBOX[x] for x in temp]
        words.append([x^y for x,y in zip(words[i-nk],temp)])
    return [sum(words[4*r:4*r+4],[]) for r in range(rounds+1)]
def encrypt_block(block,key,show=False):
    if len(block)!=16:raise ValueError('AES block must be 16 bytes.')
    keys=expand(key);state=list(block)
    def emit(stage):
        if show:print(stage,bytes(state).hex())
    if show:
        for i,k in enumerate(keys):print('Round key',i,bytes(k).hex())
    state=[a^b for a,b in zip(state,keys[0])];emit('Initial AddRoundKey')
    for r in range(1,len(keys)):
        state=[SBOX[x] for x in state];emit(f'Round {r} SubBytes')
        state=[state[4*((c+row)%4)+row] for c in range(4) for row in range(4)];emit(f'Round {r} ShiftRows')
        if r!=len(keys)-1:
            mixed=[]
            for c in range(4):
                a,b,d,e=state[4*c:4*c+4]
                mixed.extend([mul(a,2)^mul(b,3)^d^e,a^mul(b,2)^mul(d,3)^e,a^b^mul(d,2)^mul(e,3),mul(a,3)^b^d^mul(e,2)])
            state=mixed;emit(f'Round {r} MixColumns')
        state=[a^b for a,b in zip(state,keys[r])];emit(f'Round {r} AddRoundKey')
    result=bytes(state);assert result==AES.new(key,AES.MODE_ECB).encrypt(block);return result

def self_test():
    block=bytes.fromhex('00112233445566778899aabbccddeeff')
    expected={16:'69c4e0d86a7b0430d8cdb78070b4c55a',24:'dda97ca4864cdfe06eaf70a0ec0d7191',32:'8ea2b7ca516745bfeafc49904b496089'}
    for size,value in expected.items():assert encrypt_block(block,bytes(range(size))).hex()==value
    return True
def main():
    while True:
        print('\n1 Trace AES-128\n2 Trace AES-192\n3 Trace AES-256\n4 Known-answer tests\n5 Exit')
        try:
            choice=input('Input Choice: ')
            if choice=='5':return
            if choice=='4':print('Output NIST vectors:',self_test());continue
            size={'1':16,'2':24,'3':32}[choice];key=bytes(range(size));data=pad(input('Message: ').encode(),16)
            print('Output key(hex):',key.hex())
            ct=b''.join(encrypt_block(data[i:i+16],key,True) for i in range(0,len(data),16));print('Output ciphertext:',ct.hex())
        except (ValueError,KeyError) as e:print('Invalid:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
