"""Lab 4: local RSA/Rabin/ElGamal KMS, encrypted private-key vault, renewal,
revocation, audit and DRM access grants. PBKDF2-HMAC-SHA256 + AES256-GCM.
This is a single-process teaching simulation, not a deployed KMS or HIPAA proof.
Only public keys are distributed. Revocation cannot erase a recipient's old copy.
Renewal occurs when requested/check_due runs, not as an unattended scheduler.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import base64,getpass,hashlib,json,math,secrets,tempfile,time
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime
PBKDF2_ROUNDS=200000
class Vault:
    def __init__(self,folder,password,clock=time.time):
        self.folder=Path(folder);self.folder.mkdir(parents=True,exist_ok=True);self.password=password.encode();self.clock=clock
        self.path=self.folder/'registry.json';self.state=json.loads(self.path.read_text()) if self.path.exists() else {'keys':{},'audit':[],'grants':{}}
    def record(self,event,**data):
        self.state['audit'].append({'time':self.clock(),'event':event,**data});self.path.write_text(json.dumps(self.state,indent=2))
    def lock(self,data):
        salt=secrets.token_bytes(16);key=hashlib.pbkdf2_hmac('sha256',self.password,salt,PBKDF2_ROUNDS,32);cipher=AES.new(key,AES.MODE_GCM)
        ct,tag=cipher.encrypt_and_digest(json.dumps(data).encode());return dict(salt=salt.hex(),nonce=cipher.nonce.hex(),ct=ct.hex(),tag=tag.hex())
    def unlock(self,box):
        key=hashlib.pbkdf2_hmac('sha256',self.password,bytes.fromhex(box['salt']),PBKDF2_ROUNDS,32)
        return json.loads(AES.new(key,AES.MODE_GCM,nonce=bytes.fromhex(box['nonce'])).decrypt_and_verify(bytes.fromhex(box['ct']),bytes.fromhex(box['tag'])))
    def generate(self,name,algorithm='rsa',bits=2048,lifetime=86400):
        if algorithm not in ('rsa','rabin','elgamal'):raise ValueError('Unknown key type.')
        if bits not in (1024,2048,3072):raise ValueError('Choose 1024/2048/3072; 1024 is legacy lab only.')
        if lifetime<=0:raise ValueError('Lifetime must be positive.')
        if algorithm=='rsa':
            key=RSA.generate(bits);public={'pem':key.public_key().export_key().decode()};private={'pem':key.export_key().decode()}
        elif algorithm=='rabin':
            def prime():
                while True:
                    p=getPrime(bits//2)
                    if p%4==3:return p
            p,q=prime(),prime()
            while q==p:q=prime()
            public={'n':p*q};private={'p':p,'q':q}
        else:
            # PyCryptodome generates a safe-prime ElGamal group; can be slow at 2048 bits.
            from Crypto.PublicKey import ElGamal
            key=ElGamal.generate(bits,secrets.token_bytes);public={k:int(getattr(key,k)) for k in ('p','g','y')};private={'x':int(key.x)}
        previous=self.state['keys'].get(name);version=1 if previous is None else previous['version']+1
        self.state['keys'][name]=dict(algorithm=algorithm,bits=bits,version=version,public=public,private=self.lock(private),expires=self.clock()+lifetime,revoked=False)
        self.record('GENERATE_OR_ROTATE',name=name,algorithm=algorithm,version=version);return public
    def active(self,name):
        row=self.state['keys'][name]
        if row['revoked'] or self.clock()>=row['expires']:raise ValueError('Key revoked or expired.')
        return row
    def public(self,name):
        row=self.active(name);self.record('PUBLIC_DISTRIBUTION',name=name);return row['public']
    def private(self,name,actor):
        if actor!=name:self.record('DENIED_PRIVATE_ACCESS',name=name,actor=actor);raise ValueError('Only the named owner may load its private key.')
        row=self.active(name);result=self.unlock(row['private']);self.record('PRIVATE_OWNER_ACCESS',name=name);return result
    def revoke(self,name):
        self.state['keys'][name]['revoked']=True;self.record('REVOKE',name=name)
    def renew(self,name):
        row=self.state['keys'][name];return self.generate(name,row['algorithm'],row['bits'])
    def check_due(self):return [n for n,row in self.state['keys'].items() if not row['revoked'] and row['expires']<=self.clock()]
    def grant(self,document,user,seconds=3600):
        if seconds<=0:raise ValueError('Grant must have positive duration.')
        self.state['grants'].setdefault(document,{})[user]=self.clock()+seconds;self.record('GRANT',document=document,user=user)
    def revoke_grant(self,document,user):
        self.state['grants'].get(document,{}).pop(user,None);self.record('REVOKE_GRANT',document=document,user=user)
    def allowed(self,document,user):return self.state['grants'].get(document,{}).get(user,0)>self.clock()

    def encrypt_content(self,document,creator,text,master):
        row=self.active(master)
        if row['algorithm']!='elgamal':raise ValueError('DRM master must be ElGamal.')
        public=row['public'];p,g,y=(public[k] for k in ('p','g','y'));key=secrets.token_bytes(32)
        if int.from_bytes(key,'big')>=p:raise ValueError('Use a sufficiently large ElGamal modulus.')
        k=secrets.randbelow(p-3)+2;wrapped=[pow(g,k,p),int.from_bytes(key,'big')*pow(y,k,p)%p]
        cipher=AES.new(key,AES.MODE_GCM);ct,tag=cipher.encrypt_and_digest(text.encode())
        self.state.setdefault('content',{})[document]=dict(creator=creator,master=master,version=row['version'],wrapped=wrapped,nonce=cipher.nonce.hex(),ct=ct.hex(),tag=tag.hex())
        self.record('ENCRYPT_CONTENT',document=document,creator=creator)
    def creator_grant(self,document,creator,user,seconds=3600):
        if self.state['content'][document]['creator']!=creator:raise ValueError('Only content creator can grant access.')
        self.grant(document,user,seconds)
    def decrypt_content(self,document,user):
        if not self.allowed(document,user):raise ValueError('No active content grant.')
        content=self.state['content'][document];row=self.active(content['master'])
        if row['version']!=content['version']:raise ValueError('Master key rotated: creator must re-encrypt content under the new version.')
        private=self.unlock(row['private']);p=row['public']['p'];a,b=content['wrapped']
        key=(b*pow(pow(a,private['x'],p),-1,p)%p).to_bytes(32,'big')
        plain=AES.new(key,AES.MODE_GCM,nonce=bytes.fromhex(content['nonce'])).decrypt_and_verify(bytes.fromhex(content['ct']),bytes.fromhex(content['tag']))
        self.record('DECRYPT_CONTENT',document=document,user=user);return plain.decode()

def self_test():
    now=[1000]
    with tempfile.TemporaryDirectory() as folder:
        v=Vault(folder,'test-passphrase',lambda:now[0]);v.generate('hospital','rabin',1024,lifetime=10)
        public=v.public('hospital');private=v.private('hospital','hospital');assert private['p']*private['q']==public['n']
        assert '"p"' not in v.path.read_text();v.grant('book','student',10);assert v.allowed('book','student')
        try:v.private('hospital','intruder');raise AssertionError('Unauthorized access accepted')
        except ValueError:pass
        now[0]+=11;assert v.check_due()==['hospital'] and not v.allowed('book','student')
        try:v.public('hospital');raise AssertionError('Expired key accepted')
        except ValueError:pass
        v.renew('hospital');assert v.state['keys']['hospital']['version']==2
        wrong=Vault(folder,'wrong',lambda:now[0])
        try:wrong.private('hospital','hospital');raise AssertionError('Bad passphrase accepted')
        except ValueError:pass
        v.revoke('hospital')
        try:v.public('hospital');raise AssertionError('Revoked key accepted')
        except ValueError:pass
    with tempfile.TemporaryDirectory() as folder:
        v=Vault(folder,'demo');v.generate('master','elgamal',1024)
        v.encrypt_content('book','writer','Protected contents','master');v.creator_grant('book','writer','reader')
        assert v.decrypt_content('book','reader')=='Protected contents'
        v.revoke_grant('book','reader')
        try:v.decrypt_content('book','reader');raise AssertionError('Revoked content grant accepted')
        except ValueError:pass
        v.generate('rsa-server','rsa',1024);assert RSA.import_key(v.public('rsa-server')['pem']).size_in_bits()==1024
    return True

def main():
    print('Local role simulation: names are not OS authentication. Keep the vault private.')
    vault=Vault('lab_vault',getpass.getpass('Vault passphrase: '))
    while True:
        print('\n1 Generate key\n2 Distribute public key\n3 Revoke key\n4 Renew key\n5 Due keys\n6 Grant DRM access\n7 Check DRM access\n8 Revoke DRM access\n9 Audit\n10 Self-test\n11 Exit\n12 Encrypt DRM content\n13 Creator grant\n14 Decrypt DRM content')
        try:
            c=input('Input Choice: ')
            if c=='11':return
            if c=='1':print(vault.generate(input('Owner name: '),input('rsa/rabin/elgamal: '),int(input('Bits 1024/2048/3072: '))))
            elif c=='2':print(vault.public(input('Owner: ')))
            elif c=='3':vault.revoke(input('Owner: '))
            elif c=='4':print(vault.renew(input('Owner: ')))
            elif c=='5':print(vault.check_due())
            elif c=='6':vault.grant(input('Document: '),input('User: '))
            elif c=='7':print('Access allowed:',vault.allowed(input('Document: '),input('User: ')))
            elif c=='8':vault.revoke_grant(input('Document: '),input('User: '))
            elif c=='9':print(json.dumps(vault.state['audit'],indent=2))
            elif c=='10':print('PASS',self_test())
            elif c=='12':vault.encrypt_content(input('Document: '),input('Creator: '),input('Content: '),input('ElGamal master key name: '))
            elif c=='13':vault.creator_grant(input('Document: '),input('Creator: '),input('Recipient: '))
            elif c=='14':print(vault.decrypt_content(input('Document: '),input('User: ')))
            else:print('Invalid choice.')
        except (ValueError,KeyError,OSError) as e:print('Rejected:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
