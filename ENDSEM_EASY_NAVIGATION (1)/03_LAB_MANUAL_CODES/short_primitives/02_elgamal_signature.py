"""ELGAMAL SIGNATURE: tiny standalone MENU-DRIVEN lab demo.
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
LABELS = {'title': '\nELGAMAL SIGNATURE', 'menu': '1 Run demonstration\n2 Exit', 'prompt': 'Input Choice: ', 'invalid': 'Invalid input.', 'output': 'Output {label}: {value}', 'shares_bad': 'Insufficient distinct shares.', 'result_0': 'signature (r,s)', 'result_1': 'verification', 'result_2': 'tamper rejected'}
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
    p,g,x,k=467,2,127,53; y=pow(g,x,p)
    message=b'CandidateID=1;ConstituencyID=101'; m=int.from_bytes(hashlib.sha512(message).digest(),'big')%(p-1)
    r=pow(g,k,p); s=pow(k,-1,p-1)*(m-x*r)%(p-1)
    valid=pow(g,m,p)==pow(y,r,p)*pow(r,s,p)%p
    invalid=pow(g,(m+1)%(p-1),p)!=pow(y,r,p)*pow(r,s,p)%p
    out('result_0',(r,s)); out('result_1',valid); out('result_2',invalid)
    assert valid and invalid; return valid
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
