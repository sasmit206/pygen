"""Labs 1-4 PDF pp.9-13: classical substitution/transposition exercises.
Menu driven; A-Z normalization for substitution. Playfair merges J into I and
inserts X/Q fillers: decryption returns PREPARED plaintext, since fillers cannot
be removed unambiguously. Hill uses column vectors and row-major [[3,3],[2,7]].
Classical ciphers are educational and are not byte-preserving payload adapters.
"""
# QUICK EDIT: set ALGORITHM to the wanted cipher (or choose from the menu).
# KEYS below holds each demo key; edit the matching entry for your paper.
# main() takes plaintext/ciphertext and optional key input.

import math,string,itertools
ALGORITHM='autokey'
KEYS={'caesar':20,'multiplicative':15,'affine':(15,20),'vigenere':'DOLLARS','autokey':7,
      'playfair':'GUIDANCE','hill':(3,3,2,7),'rail_fence':3,'keyed_transposition':(2,0,1),
      'columnar':'ZEBRAS','double_transposition':('ZEBRAS','HEALTH')}
NAMES=list(KEYS)
def letters(text):return ''.join(c for c in text.upper() if c in string.ascii_uppercase)
def matrix_inverse(key):
    a,b,c,d=key;inv=pow((a*d-b*c)%26,-1,26);return (d*inv%26,-b*inv%26,-c*inv%26,a*inv%26)
def playfair_prepare(text):
    text=letters(text).replace('J','I');out='';i=0
    while i<len(text):
        a=text[i];filler='Q' if a=='X' else 'X'
        if i+1==len(text) or text[i+1]==a:out+=a+filler;i+=1
        else:out+=text[i:i+2];i+=2
    return out
def playfair(text,key,decrypt=False):
    square=''.join(dict.fromkeys(letters(key).replace('J','I')+'ABCDEFGHIKLMNOPQRSTUVWXYZ'))
    pos={c:divmod(i,5) for i,c in enumerate(square)};text=letters(text) if decrypt else playfair_prepare(text)
    if len(text)%2:raise ValueError('Playfair ciphertext must have even length.')
    out='';step=-1 if decrypt else 1
    for i in range(0,len(text),2):
        r1,c1=pos[text[i]];r2,c2=pos[text[i+1]]
        if r1==r2:c1=(c1+step)%5;c2=(c2+step)%5
        elif c1==c2:r1=(r1+step)%5;r2=(r2+step)%5
        else:c1,c2=c2,c1
        out+=square[r1*5+c1]+square[r2*5+c2]
    return out

def column_order(size,key):
    width=len(key);columns=sorted(range(width),key=lambda i:(key[i],i))
    return [i for c in columns for i in range(c,size,width)]
def permutation(text,order,decrypt):
    if not decrypt:return ''.join(text[i] for i in order)
    out=['']*len(text)
    for c,i in zip(text,order):out[i]=c
    return ''.join(out)
def crypt(text,name,key=None,decrypt=False):
    key=KEYS[name] if key is None else key
    if name in ('rail_fence','keyed_transposition','columnar','double_transposition'):
        if name=='rail_fence':
            if key<2:raise ValueError('Use at least two rails.')
            route=[min(i%(2*key-2),2*key-2-i%(2*key-2)) for i in range(len(text))]
            order=sorted(range(len(text)),key=lambda i:route[i])
        elif name=='keyed_transposition':
            if sorted(key)!=list(range(len(key))):raise ValueError('Invalid permutation.')
            order=[base+i for base in range(0,len(text),len(key)) for i in key if base+i<len(text)]
        elif name=='columnar':order=column_order(len(text),key)
        else:
            first,second=key
            if decrypt:return crypt(crypt(text,'columnar',second,True),'columnar',first,True)
            return crypt(crypt(text,'columnar',first),'columnar',second)
        return permutation(text,order,decrypt)
    text=letters(text)
    if name=='playfair':return playfair(text,key,decrypt)
    if name=='hill':
        if decrypt and len(text)%2:raise ValueError('Even-length ciphertext required.')
        if len(text)%2:text+='X'
        a,b,c,d=matrix_inverse(key) if decrypt else key;out=''
        matrix_inverse(key) # Reject a non-invertible key even during encryption.
        for i in range(0,len(text),2):
            x,y=ord(text[i])-65,ord(text[i+1])-65;out+=chr((a*x+b*y)%26+65)+chr((c*x+d*y)%26+65)
        return out
    out=[];values=[ord(c)-65 for c in text]
    for i,x in enumerate(values):
        if name in ('caesar','multiplicative','affine'):
            a,b=(1,key) if name=='caesar' else (key,0) if name=='multiplicative' else key
            inverse=pow(a,-1,26);value=(inverse*(x-b) if decrypt else a*x+b)%26
        else:
            if name=='vigenere':
                clean=letters(key)
                if not clean:raise ValueError('Empty keyword.')
                shift=ord(clean[i%len(clean)])-65
            else:shift=key if i==0 else (out[i-1] if decrypt else values[i-1])
            value=(x-shift if decrypt else x+shift)%26
        out.append(value)
    return ''.join(chr(x+65) for x in out)
def self_test():
    for name in NAMES:
        raw='WE LIVE IN AN INSECURE WORLD';ct=crypt(raw,name);recovered=crypt(ct,name,decrypt=True)
        expected=raw if name in ('rail_fence','keyed_transposition','columnar','double_transposition') else playfair_prepare(raw) if name=='playfair' else letters(raw)
        if name=='hill' and len(expected)%2:expected+='X'
        assert recovered==expected,(name,recovered,expected)
    assert crypt('ATTACKATDAWN','vigenere','LEMON')=='LXFOPVEFRNHR'
    assert crypt('ACT','hill',(3,3,2,5))=='GKWX' # ACTX under the stated column convention.
    assert crypt('INSTRUMENTS','playfair','MONARCHY')=='GATLMZCLRQXA'
    return True

def main():
    while True:
        print('\nCLASSICAL CIPHERS\n1 Encrypt\n2 Decrypt\n3 Run round-trip checks\n4 Exit')
        try:
            choice=input('Input Choice: ').strip()
            if choice=='4':return
            if choice=='3':print('Output checks:',self_test());continue
            if choice not in ('1','2'):raise ValueError('Choose 1-4.')
            name=ALGORITHM
            if name=='choose':
                for i,n in enumerate(NAMES,1):print(i,n)
                number=int(input('Algorithm number: '))
                if not 1<=number<=len(NAMES):raise ValueError('Algorithm number out of range.')
                name=NAMES[number-1]
            text=input('Text: ');print('Output key:',KEYS[name]);print('Output result:',crypt(text,name,decrypt=choice=='2'))
        except (ValueError,KeyError,IndexError) as e:print('Rejected:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
