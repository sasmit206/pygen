"""Lab 8 Snort preparation: write three synthetic IPv4/UDP packets to a PCAP.
No packets are sent. Writes matching local Snort rules; --run requires installed
Snort 3 and its real snort.lua configuration. Python checks are NOT Snort tests.
"""
# QUICK EDIT: search for main() for menu/input prompts, demo() or self_test()
# for example inputs, and constants near imports for lab parameters.
# Keep key sizes, ranges and verification checks consistent when changing values.

import shutil,socket,struct,subprocess,time
from pathlib import Path
RULE='alert udp any any -> any 9999 (msg:"LAB suspicious marker"; content:"LAB_ALERT"; sid:1000001; rev:1;)\n'
def checksum(raw):
    if len(raw)%2:raw+=b'\0'
    total=sum(struct.unpack('!'+str(len(raw)//2)+'H',raw));total=(total&65535)+(total>>16);total=(total&65535)+(total>>16);return (~total)&65535

def packet(payload,port=9999):
    src,dst=socket.inet_aton('192.0.2.10'),socket.inet_aton('192.0.2.20');length=8+len(payload)
    udp=struct.pack('!HHHH',45000,port,length,0)+payload;pseudo=src+dst+struct.pack('!BBH',0,17,length)
    value=checksum(pseudo+udp) or 65535;udp=udp[:6]+struct.pack('!H',value)+udp[8:]
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+length,1,0,64,17,0,src,dst);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    ethernet=bytes.fromhex('0200000000020200000000010800');return ethernet+ip+udp

def generate(folder):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True);frames=[packet(b'normal lab traffic'),packet(b'LAB_ALERT suspicious marker'),packet(b'LAB_ALERT wrong port',8888)]
    data=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
    for i,frame in enumerate(frames):data+=struct.pack('<IIII',1700000000+i,0,len(frame),len(frame))+frame
    (folder/'lab.pcap').write_bytes(data);(folder/'local.rules').write_text(RULE);return folder/'lab.pcap'

def inspect(path):
    raw=Path(path).read_bytes();assert struct.unpack('<IHHIIII',raw[:24])==(0xa1b2c3d4,2,4,0,0,65535,1);pos=24;count=matches=0
    while pos<len(raw):
        _,_,size,original=struct.unpack('<IIII',raw[pos:pos+16]);pos+=16;frame=raw[pos:pos+size];pos+=size;assert len(frame)==size==original
        ip=frame[14:34];udp=frame[34:];assert checksum(ip)==0
        assert checksum(ip[12:20]+struct.pack('!BBH',0,17,len(udp))+udp)==0
        matches+=int(struct.unpack('!H',udp[2:4])[0]==9999 and b'LAB_ALERT' in udp[8:]);count+=1
    assert count==3 and matches==1
    return {'packets':count,'expected_rule_matches':matches,'python_packet_validation':'PASS','snort_engine':'NOT RUN'}

def main():
    while True:
        print('\n1 Generate PCAP/rules and validate packet checksums\n2 Run installed Snort 3 offline\n3 Exit')
        try:
            c=input('Input Choice: ')
            if c=='3':return
            if c=='1':print(inspect(generate('snort_lab')))
            elif c=='2':
                binary=shutil.which('snort')
                if not binary:raise ValueError('Snort is not installed. See SNORT_RUNBOOK.txt.')
                config=Path(input('Absolute path to your snort.lua: ')).resolve()
                if not config.is_file():raise ValueError('Configuration file missing.')
                pcap=generate('snort_lab').resolve();command=[binary,'-q','-c',str(config),'-r',str(pcap),'-R',str(pcap.parent/'local.rules'),'-A','alert_fast']
                print('Running:',command);result=subprocess.run(command,check=False);print('Snort exit status:',result.returncode)
            else:print('Invalid choice.')
        except (ValueError,OSError) as e:print('Error:',e)
        except (EOFError,KeyboardInterrupt):return
if __name__=='__main__':main()
