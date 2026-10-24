"""Lab 8: real GnuPG public-key exchange, signed encryption, decryption,
detached signature and tamper rejection. Requires installed gpg executable.
Creates separate temporary Alice/Bob keyrings, never touches your normal keyring.
Unprotected throwaway demo keys are deleted afterward; no external messages sent.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import os,shutil,subprocess,tempfile
from pathlib import Path

def demo(text='Information Security Lab'):
    executable=shutil.which('gpg')
    if not executable:raise RuntimeError('Install GnuPG and ensure gpg is on PATH.')
    homes=[]
    with tempfile.TemporaryDirectory(prefix='lab-gpg-') as folder:
        base=Path(folder)
        def run(home,*args,data=None,check=True):
            command=[executable,'--homedir',str(home),'--batch','--yes','--pinentry-mode','loopback','--passphrase','',*args]
            result=subprocess.run(command,input=data,capture_output=True,timeout=120)
            if check and result.returncode:raise RuntimeError(result.stderr.decode(errors='replace'))
            return result
        try:
            keys={}
            for name in ('alice','bob'):
                home=base/name;home.mkdir(mode=0o700);homes.append(home)
                run(home,'--quick-generate-key',f'{name} Lab <{name}@example.invalid>','rsa2048','sign','1d')
                listing=run(home,'--with-colons','--list-secret-keys').stdout.decode()
                fingerprint=next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
                run(home,'--quick-add-key',fingerprint,'rsa2048','encrypt','1d');keys[name]=fingerprint
            alice,bob=homes
            run(bob,'--import',data=run(alice,'--armor','--export',keys['alice']).stdout)
            run(alice,'--import',data=run(bob,'--armor','--export',keys['bob']).stdout)
            encrypted=run(alice,'--trust-model','always','--armor','--local-user',keys['alice'],'--recipient',keys['bob'],'--sign','--encrypt',data=text.encode()).stdout
            result=run(bob,'--status-fd','2','--decrypt',data=encrypted)
            assert result.stdout==text.encode() and b'[GNUPG:] VALIDSIG '+keys['alice'].encode() in result.stderr
            message=base/'message.txt';message.write_text(text,encoding='utf-8');signature=base/'message.sig'
            run(alice,'--local-user',keys['alice'],'--output',str(signature),'--detach-sign',str(message))
            run(bob,'--verify',str(signature),str(message));message.write_bytes(text.encode()+b' tampered')
            bad=run(bob,'--verify',str(signature),str(message),check=False);assert bad.returncode!=0
            return {'gpg_version':subprocess.run([executable,'--version'],capture_output=True,text=True).stdout.splitlines()[0],'public_key_exchange':True,'decrypted_message':result.stdout.decode(),'valid_signature':True,'tamper_rejected':True}
        finally:
            gpgconf=shutil.which('gpgconf')
            if gpgconf:
                for home in homes:subprocess.run([gpgconf,'--homedir',str(home),'--kill','gpg-agent'],capture_output=True)

def main():
    while True:
        print('\n1 Encrypt/sign/verify between isolated local keyrings\n2 Exit')
        try:
            c=input('Input Choice: ')
            if c=='2':return
            if c=='1':print(demo(input('Message: ')))
            else:print('Invalid choice.')
        except (RuntimeError,OSError,subprocess.TimeoutExpired) as e:print('Error:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
