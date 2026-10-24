"""Lab 5 pp.1-3: 5381/33 32-bit hash, integrity and 50-100 string benchmark.
The manual does not define extra XOR mixing: this implements the stated djb2 add
recurrence h=((h<<5)+h+ord(character)) & 0xffffffff. It is NOT cryptographic.
A small random dataset finding no collision does NOT establish collision resistance.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import hashlib,random,string,time

def djb2(text):
    h=5381
    for c in text:h=((h<<5)+h+ord(c))&0xffffffff
    return h

def hashes(text):
    raw=text.encode();return {'djb2_32':f'{djb2(text):08x}',**{a:hashlib.new(a,raw).hexdigest() for a in ['md5','sha1','sha256','sha512','sha3_256']}}
def benchmark(count=100):
    if not 50<=count<=100:raise ValueError('Use 50 to 100 messages.')
    rng=random.Random(3141);data=[''.join(rng.choices(string.ascii_letters+string.digits,k=32)) for _ in range(count)];result=[]
    for algorithm in ['md5','sha1','sha256']:
        seen={};collisions=[];start=time.perf_counter()
        for text in data:
            value=hashlib.new(algorithm,text.encode()).hexdigest()
            if value in seen and seen[value]!=text:collisions.append([seen[value],text])
            seen[value]=text
        result.append({'algorithm':algorithm,'seconds':time.perf_counter()-start,'distinct_inputs':len(set(data)),'collisions':collisions})
    return result

def main():
    while True:
        print('\n1 Hash a message\n2 Tamper demonstration\n3 Benchmark 100 random strings\n4 Exit')
        try:
            c=input('Input Choice: ')
            if c=='4':return
            if c=='1':print(hashes(input('Message: ')))
            elif c=='2':
                text=input('Original: ');changed=input('Received: ');print('Output integrity match:',hashes(text)==hashes(changed))
            elif c=='3':
                for row in benchmark():print(row)
                print('No observed collisions is not proof of cryptographic strength.')
            else:print('Invalid choice.')
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
