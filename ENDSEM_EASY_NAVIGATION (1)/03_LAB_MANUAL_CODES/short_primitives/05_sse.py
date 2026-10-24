"""HMAC SEARCH INDEX: tiny standalone MENU-DRIVEN lab demo.
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
LABELS = {'title': '\nHMAC SEARCH INDEX', 'menu': '1 Run demonstration\n2 Exit', 'prompt': 'Input Choice: ', 'invalid': 'Invalid input.', 'output': 'Output {label}: {value}', 'shares_bad': 'Insufficient distinct shares.', 'result_0': 'stored opaque index', 'result_1': 'search for group 101'}
# ================= ZONE 2: ROLES =================
# Single-user primitive exercise; no role menus are needed.
# ================= ZONE 3: PARAMETERS =================
# Small educational parameters are shown beside each primitive formula.
# ================= ZONE 4: DEMONSTRATION POLICY =================
# Fixed examples only; use the full answers for DEMO/REAL and RBAC flags.
# ================= ZONE 5: MENU =================
MENU_ACTIONS = {'1':'demo', '2':None}
# ================= ZONE 6: PRIMITIVE =================

def token(field,value): return hmac.new(bytes(range(32)),json.dumps([field,str(value)]).encode(),hashlib.sha256).hexdigest()
def demo():
    index={token('group',101):[1,3],token('group',102):[2]}
    result=index.get(token('group',101),[])
    # Check whole decoded keys, not accidental short hex substrings such as "101".
    assert all(len(k)==64 and k!=str(101) and k!=str(102) for k in index)
    out('result_0',index); out('result_1',result)
    assert result==[1,3]; return result
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
