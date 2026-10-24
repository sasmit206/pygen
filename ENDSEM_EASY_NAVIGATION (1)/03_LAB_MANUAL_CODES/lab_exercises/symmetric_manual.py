"""Lab 2 exact message/key exercises, with explicit key-encoding corrections.
CBC and ECB use PKCS7. CTR uses the manual's 8-byte hex nonce + counter 0.
Fixed demo IVs are not recommendations for real encryption.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

from Crypto.Cipher import AES,DES,DES3
from Crypto.Util.Padding import pad,unpad

def roundtrip(module,key,mode,raw,**options):
    number=getattr(module,'MODE_'+mode);prepared=pad(raw,module.block_size) if mode in ('ECB','CBC') else raw
    ct=module.new(key,number,**options).encrypt(prepared);plain=module.new(key,number,**options).decrypt(ct)
    if mode in ('ECB','CBC'):plain=unpad(plain,module.block_size)
    assert plain==raw;return dict(mode=mode,key_hex=key.hex(),ciphertext_hex=ct.hex(),plaintext=plain.decode())
def examples():
    rows=[]
    rows.append(roundtrip(DES,b'A1B2C3D4','ECB',b'Confidential Data'))
    rows[-1]['note']='DES key interpreted as eight ASCII bytes; ECB chosen because this question omits a mode.'
    rows.append(roundtrip(AES,bytes.fromhex('0123456789ABCDEF'*2),'ECB',b'Sensitive Information'))
    bad=bytes.fromhex('1234567890ABCDEF'*3)
    try:DES3.new(bad,DES3.MODE_ECB);raise AssertionError('Degenerate key unexpectedly accepted')
    except ValueError as e:rows.append({'manual_3DES_key_rejected':str(e),'reason':'K1=K2=K3, reducing EDE to single DES.'})
    key=DES3.adjust_key_parity(bytes.fromhex('0123456789ABCDEFFEDCBA98765432100011223344556677'))
    rows.append(roundtrip(DES3,key,'ECB',b'Classified Text'));rows[-1]['note']='Explicit replacement key; not the invalid manual key.'
    invalid=bytes.fromhex('FEDCBA9876543210'*2);assert len(invalid)==16
    rows.append({'manual_AES192_key_bytes':16,'required':24,'correction':'Use an explicitly supplied 24-byte key; aes_round_trace.py demonstrates bytes 00..17.'})
    rows.append(roundtrip(AES,bytes.fromhex('0123456789ABCDEF'*4),'ECB',b'Encryption Strength'))
    rows.append(roundtrip(DES,b'A1B2C3D4','CBC',b'Secure Communication',iv=b'12345678'))
    rows.append(roundtrip(AES,bytes.fromhex('0123456789ABCDEF'*2),'CTR',b'Cryptography Lab Exercise',nonce=bytes.fromhex('0000000000000000'),initial_value=0))
    for value in ('54686973206973206120636f6e666964656e7469616c206d657373616765','416e64207468697320697320746865207365636f6e6420626c6f636b'):
        rows.append(roundtrip(DES,bytes.fromhex('A1B2C3D4E5F60708'),'ECB',bytes.fromhex(value)))
    return rows

def main():
    while True:
        print('\n1 Run manual messages and show invalid-key corrections\n2 Exit')
        try:
            c=input('Input Choice: ')
            if c=='2':return
            if c=='1':
                for row in examples():print(row)
            else:print('Invalid choice.')
        except ValueError as e:print('Rejected:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
