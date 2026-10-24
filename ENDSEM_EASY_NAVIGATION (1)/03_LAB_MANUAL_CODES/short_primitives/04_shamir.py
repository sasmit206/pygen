"""SHAMIR 2-OF-3 RECONSTRUCTION: tiny standalone MENU-DRIVEN lab demo.
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
LABELS = {'title': '\nSHAMIR 2-OF-3 RECONSTRUCTION', 'menu': '1 Run demonstration\n2 Exit', 'prompt': 'Input Choice: ', 'invalid': 'Invalid input.', 'output': 'Output {label}: {value}', 'shares_bad': 'Insufficient distinct shares.', 'result_0': 'shares', 'result_1': 'temporarily reconstructed secret'}
# ================= ZONE 2: ROLES =================
# Single-user primitive exercise; no role menus are needed.
# ================= ZONE 3: PARAMETERS =================
# Small educational parameters are shown beside each primitive formula.
# ================= ZONE 4: DEMONSTRATION POLICY =================
# Fixed examples only; use the full answers for DEMO/REAL and RBAC flags.
# ================= ZONE 5: MENU =================
MENU_ACTIONS = {'1':'demo', '2':None}
# ================= ZONE 6: PRIMITIVE =================

def recover(shares):
    if len(shares)<2 or len(set(x for x,y in shares))!=len(shares): raise ValueError(LABELS['shares_bad'])
    prime=2089; result=0
    for x,y in shares:
        a=b=1
        for u,v in shares:
            if u!=x: a=a*(-u)%prime; b=b*(x-u)%prime
        result=(result+y*a*pow(b,-1,prime))%prime
    return result
def demo():
    secret=123; shares=[(x,(secret+71*x)%2089) for x in [1,2,3]]
    result=recover([shares[0],shares[2]])
    out('result_0',shares); out('result_1',result)
    assert result==secret; return result
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
