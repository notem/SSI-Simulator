import sys
import subprocess
import time
#import paramiko

if len(sys.argv) < 5:
    raise UserWarning("Please use two or more parameters")

device_num = sys.argv[1]
experiment_num = sys.argv[2]
scan_time = sys.argv[3]
devices = sys.argv[4]
action = sys.argv[5]


port=22
s_attacker=30
victimsend=45
target=int(device_num)+1

sshtunnel=""

def get_commands(cmdfile):
    cmds=[]
    with open(cmdfile, 'r') as cf:
        for cmd in cf:
            cmds.append(cmd)
    print(cmds)

def ssh_tunnel(target, port):
    if int(target) < int(devices):
        tunnel=subprocess.Popen(f"ssh -A -t -p 22 dev{target}", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        tunnel.communicate(f"python3 /opt/internal.py {target} {experiment_num} {scan_time} {devices} 1".encode())
        if device_num == 1:
            cmds=get_commands("/opt/cmd.txt")
            for cmd in cmds:
                res=tunnel.communicate(bytes(cmd))
                print(str(res[0]))

#Main method----

subprocess.run("service ssh restart", shell=True)
#subprocess.run("timeout 10 tcpdump -i eth0 -U -w /purple/tcpdump/"+experiment_num+"/dev"+device_num+".pcap &", shell=True)


if int(action) == 1:
    ssh_tunnel(str(target), 22)
else:
    subprocess.run("timeout 10 tcpdump -i eth0 -U -w /purple/tcpdump/"+experiment_num+"/dev"+device_num+".pcap &", shell=True)
    time.sleep(int(scan_time))
