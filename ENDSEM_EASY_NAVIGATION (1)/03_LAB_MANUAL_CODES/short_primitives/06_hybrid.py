"""RSA-OAEP / AES-GCM HYBRID: tiny standalone MENU-DRIVEN lab demo.
Python 3.10+; install pycryptodome. Fixed small parameters are educational only.
Run this file, select 1, then 2 to exit. No file outside this script is required.
"""
import hashlib, hmac, json, math
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

# QUICK EDIT: change LABELS for wording; change values inside demo() for
# sample inputs. Keep the math and its matching assert together when editing.
# ================= ZONE 1: ALL OUTPUT LABELS =================
LABELS = {'title': '\nRSA-OAEP / AES-GCM HYBRID', 'menu': '1 Run demonstration\n2 Exit', 'prompt': 'Input Choice: ', 'invalid': 'Invalid input.', 'output': 'Output {label}: {value}', 'shares_bad': 'Insufficient distinct shares.', 'result_0': 'AES ciphertext', 'result_1': 'wrapped key bytes', 'result_2': 'round trip'}
# ================= ZONE 2: ROLES =================
# Single-user primitive exercise; no role menus are needed.
# ================= ZONE 3: PARAMETERS =================
# Small educational parameters are shown beside each primitive formula.
# ================= ZONE 4: DEMONSTRATION POLICY =================
# Fixed examples only; use the full answers for DEMO/REAL and RBAC flags.
# ================= ZONE 5: MENU =================
MENU_ACTIONS = {'1':'demo', '2':None}
# ================= ZONE 6: PRIMITIVE =================

def demo():
    rsa=RSA.generate(2048); key=bytes(range(32)); nonce=bytes(range(12)); raw=b'sample payload'
    c=AES.new(key,AES.MODE_GCM,nonce=nonce); ct,tag=c.encrypt_and_digest(raw)
    wrapped=PKCS1_OAEP.new(rsa.public_key(),hashAlgo=SHA256).encrypt(key)
    recovered=PKCS1_OAEP.new(rsa,hashAlgo=SHA256).decrypt(wrapped)
    result=AES.new(recovered,AES.MODE_GCM,nonce=nonce).decrypt_and_verify(ct,tag)
    out('result_0',ct.hex()); out('result_1',len(wrapped)); out('result_2',result==raw)
    assert result==raw; return True
# ================= ZONE 7: DISPLAY / MAIN =================
def out(label,value): print(LABELS['output'].format(label=LABELS[label],value=value))

def main():
    while True:
        print(LABELS['title']); print(LABELS['menu'])
        try:
            choice=input(LABELS['prompt']).strip()
            if choice in MENU_ACTIONS and MENU_ACTIONS[choice] is None: return
            if choice in MENU_ACTIONS: globals()[MENU_ACTIONS[choice]]()
            else: print(LABELS['invalid'])
        except (ValueError,EOFError,KeyboardInterrupt): return
if __name__=='__main__': main()
