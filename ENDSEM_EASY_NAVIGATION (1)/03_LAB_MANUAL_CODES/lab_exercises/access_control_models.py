"""Lab 4 pp.38-39: executable RBAC, ABAC, Bell-LaPadula, MAC, DAC,
time-window and probabilistic policy models. Toy policies, not OS enforcement.
Security levels: public=0, internal=1, confidential=2, secret=3.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import random
USERS={'alice':{'role':'doctor','department':'health','clearance':2,'trust':0.9},'bob':{'role':'clerk','department':'finance','clearance':1,'trust':0.5}}
OBJECT={'owner':'alice','department':'health','classification':2}
ROLES={'doctor':{'read','write'},'clerk':{'read'}}
RIGHTS={'alice':{'read','write'},'bob':set()}
REVOKED=set()
def allowed(model,user,action,now=12,risk=0.2,draw=None):
    if user in REVOKED or user not in USERS or action not in ('read','write'):return False
    u=USERS[user]
    if model=='rbac':return action in ROLES[u['role']]
    if model=='abac':return u['department']==OBJECT['department'] and u['clearance']>=OBJECT['classification'] and 9<=now<=17
    if model=='bell_lapadula':return u['clearance']>=OBJECT['classification'] if action=='read' else u['clearance']<=OBJECT['classification']
    if model=='mac':return u['clearance']>=OBJECT['classification'] and action in ROLES[u['role']]
    if model=='dac':return action in RIGHTS[user]
    if model=='time':return 9<=now<=17 and action in ROLES[u['role']]
    if model=='probabilistic':
        probability=max(0,min(1,u['trust']*(1-risk)));return (random.random() if draw is None else draw)<probability
    raise ValueError('Unknown policy.')
def self_test():
    assert allowed('rbac','alice','write') and not allowed('rbac','bob','write')
    assert allowed('abac','alice','read') and not allowed('abac','bob','read')
    assert not allowed('bell_lapadula','bob','read') and allowed('bell_lapadula','bob','write')
    assert not allowed('mac','bob','read') and not allowed('dac','bob','read')
    assert not allowed('time','alice','read',now=18)
    assert allowed('probabilistic','alice','read',draw=0.1) and not allowed('probabilistic','alice','read',draw=0.99)
    REVOKED.add('alice');assert not allowed('rbac','alice','read');REVOKED.clear();return True
def main():
    while True:
        print('\n1 Evaluate policy\n2 Revoke user\n3 Grant DAC read\n4 Self-test\n5 Exit')
        try:
            c=input('Input Choice: ')
            if c=='5':return
            if c=='1':print('Output access:',allowed(input('Model (rbac/abac/bell_lapadula/mac/dac/time/probabilistic): '),input('User (alice/bob): '),input('Action (read/write): '),float(input('Hour (0-23): '))))
            elif c=='2':REVOKED.add(input('User: '))
            elif c=='3':RIGHTS[input('User: ')].add('read')
            elif c=='4':print(self_test())
            else:print('Invalid choice.')
        except (ValueError,KeyError) as e:print(e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
