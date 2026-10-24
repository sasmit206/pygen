"""DIFFIE-HELLMAN AGREEMENT: tiny standalone MENU-DRIVEN lab demo.
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
LABELS = {'title': '\nDIFFIE-HELLMAN AGREEMENT', 'menu': '1 Run demonstration\n2 Exit', 'prompt': 'Input Choice: ', 'invalid': 'Invalid input.', 'output': 'Output {label}: {value}', 'shares_bad': 'Insufficient distinct shares.', 'result_0': 'public contributions', 'result_1': 'derived keys match', 'result_2': 'derived key DEMO ONLY'}
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
    p,g,a,b=467,2,127,71; A,B=pow(g,a,p),pow(g,b,p)
    first,second=pow(B,a,p),pow(A,b,p)
    key1=hashlib.sha256(str(first).encode()).digest(); key2=hashlib.sha256(str(second).encode()).digest()
    out('result_0',(A,B)); out('result_1',key1==key2)
    out('result_2',key1.hex()); assert key1==key2; return True
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
