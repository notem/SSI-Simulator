#!/usr/bin/python3

import sys
import subprocess
import time
import random
import os
import json
import pickle


tunnel_build_delay = lambda: random.uniform(0.5,1.5)
tunnel_down_delay = lambda: random.uniform(0.5,1.5)


ICMP_PORT = 2222
SOCAT_PORT = 3333

def build_tunnel(tunnel_type, socat_port=SOCAT_PORT, icmp_port=ICMP_PORT):
    """Construct tunnel iteratively
    """
    # opts for SSH to prevent host checking causing hang-ups
    ssh_opts = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
    step_sleep = 0.2

    session_name = "mySession"
    subprocess.run(f"tmux new -d -s {session_name}", shell=True)

    #For any tunnel of n>=3 i[0]=1, i[1]=2, i[2]=3, even if i[3]=n. A special cases cases will be added later for n=1 and n=2
    for i,tunnel in enumerate(tunnel_type):
        hostname = f'dev{i+2}'
        if tunnel == "ssh":
            cmd=f"ssh {ssh_opts} -tt {hostname}"
            time.sleep(step_sleep)

        elif tunnel == "socat":
            cmd = f"socat FILE:\`tty\`,raw,echo=0 tcp-connect:{hostname}:{socat_port}"
            time.sleep(step_sleep)

        elif tunnel == "icmp":
            # create ptunnel proxy connection
            service_cmd = f'ptunnel-ng -d -p{hostname} -l{icmp_port} -rlocalhost -R22 -v-1'
            subprocess.run(f'tmux send-keys -t {session_name}.0 "{service_cmd}" Enter', shell=True)
            time.sleep(step_sleep) # small sleep to let service start

            # open SSH connection to proxy host
            cmd = f"ssh {ssh_opts} -tt -p{icmp_port} localhost"  

        # add additional protocol tunnel establishing stuff here
        #elif tunnel == "DNS":
        #    cmd = f"dnstunnel {hostname}" 

        else:
            raise UserWarning(f"Invalid tunnel type {tunnel}.")

        # extend tunnel to next hop
        print(f" [{i}/{len(tunnel_type)}] Extending tunnel to {hostname} with {tunnel}.")
        subprocess.run(f'tmux send-keys -t {session_name}.0 "{cmd}" Enter', shell=True)
        time.sleep(tunnel_build_delay())  # connection may take a moment to establish, wait to try to avoid issue
        time.sleep(step_sleep)

    return session_name


#def send_commands(session_name, 
#        cmd_options = ['pwd','ls /','time','hostname','blsk']
#        command_count = 10):
#    """Send commands / keystrokes to tmux with tunnel
#       Only runs on the first host
#    """
#    for _ in range(command_count):
#        cmd = random.choice(cmds)
#        subprocess.run(f'tmux send-keys -t {session_name}.0 "{cmd}" Enter', shell=True)
#        time.sleep(random.randint(1,10))


def send_commands(session_name, 
        snddist, rcvdist, delaydist, 
        command_count=10):
    """
    """
    for i in range(command_count):
        # sample send & recv sizes
        recv_target = random.choice(rcvdist)
        send_target = random.choice(snddist)

        # construct cmd string & send to tunnel
        send_len = 7+len(str(recv_target))
        send_pad = '0' * max(0, send_target - send_len)
        cmd = f'n={recv_target};u={send_pad};a'
        print(f" [{i+1}/{command_count}] Sending cmd with {send_target} send and {recv_target} recv chars.")
        subprocess.run(f'tmux send-keys -t {session_name}.0 "{cmd}" Enter', shell=True)

        # sleep for delay
        delay_target = random.choice(delaydist)
        print(f" [{i+1}/{command_count}] Sleep for {delay_target}s.")
        time.sleep(delay_target)


def start_listeners(socat_port=SOCAT_PORT):
    """Initialize listening services on stepping-stone hosts
    """
    # start SSH listener daemon
    subprocess.run('service ssh start > /dev/null', shell=True)
    
    # start socat listener in background tmux pane
    subprocess.run(f"tmux new -d -s socat", shell=True)
    socat_cmd = f'socat tcp-listen:{socat_port},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane'
    subprocess.run(f'tmux send-keys -t socat.0 "{socat_cmd}" Enter', shell=True)

    # start ICMP tunnel listener
    subprocess.run('tmux new -d -s icmpserver', shell=True)
    icmp_cmd = f'ptunnel-ng -rlocalhost -R22' # configure proxy to only allow ssh connections to itself
    subprocess.run(f'tmux send-keys -t icmpserver.0 "{icmp_cmd}" Enter', shell=True)

    # start dns tunnel listening script
    #subprocess.run(f"tmux new -d -s dnslistener", shell=True)
    #dns_cmd = f"bash dnstunnel.sh"
    #subprocess.run(f'tmux send-keys -t dns.0 "{dns_cmd}" Enter', shell=True)
    
    # DEBUG: verify listeners are listening as expected
    #subprocess.run('netstat -antp', shell=True)


def tunnel_randomizer(tunnel_length, tunnel_types):
    """create random tunnel protocol sequence
    """
    c=0
    stages=[]
    while c<tunnel_length:
        stages.append(random.choice(tunnel_types))
        c=c+1
    return stages


# TODO it is not clear to me if netem delays are working as expected; needs to be investigated
def set_delay(mean=200, deviation=10, distribution='normal', device='eth0'):
    """
    distribution options: 'normal', 'pareto', 'paretonormal'
    """
    cmd_str = f'tc qdisc add dev {device} root netem delay {mean}ms {deviation}ms'
    if distribution is not None:
        cmd_str = f'{cmd_str} distribution {distribution}'
    subprocess.run(cmd_str, shell=True)


#+=======Main method=========+
if __name__ == "__main__":

    if len(sys.argv) < 5:
        raise UserWarning("Please use five or more parameters")
    
    device_num = sys.argv[1]
    experiment_num = sys.argv[2]
    scan_time = sys.argv[3]
    devices = sys.argv[4]

    # setup directory & file paths
    results_root = f"/purple/results/{experiment_num}"
    if not os.path.exists(results_root):
        os.makedirs(results_root)
    tcpdump_root = os.path.join(results_root, "tcpdump")
    if not os.path.exists(tcpdump_root):
        os.makedirs(tcpdump_root)

    pcap_loc = os.path.join(tcpdump_root, f"dev{device_num}.pcap")

    # build tcpdump capture command
    net_device = "eth0"
    ip_cmd = f"ip -4 addr show {net_device} | grep -oP '(?<=inet\s)\d+(\.\d+){3}'"
    tcpdump_cmd = f"timeout {scan_time} tcpdump -i {net_device} -U -w {pcap_loc}"# -n host $({ip_cmd})"

    # attacker host
    if int(device_num) == 1:
        # TODO mean&deviation should differ between runs
        set_delay(mean=200, deviation=50)  # WAN delay 
    
        # start traffic capture (in the background)
        subprocess.run(tcpdump_cmd+" &", shell=True)
        time.sleep(2)   # wait 2 seconds before building tunnel to avoid missing packets
    
        # build tunnel
        # tunnel is protocols are randomly selected for each hop
        tunnel_options = ['socat', 'ssh', 'icmp']
        #tunnel_options = ['ssh']
        #tunnel_options = ['icmp']
        tunnel = tunnel_randomizer((int(devices)-1), tunnel_options)
        session_name = build_tunnel(tunnel)

        # log tunnel protocol info to results directory
        tun_loc = os.path.join(results_root, 'tunnel.json')
        with open(tun_loc, 'w') as fi:
            data = {f'dev{i+2}': proto for i,proto in enumerate(tunnel)}
            json.dump(data, fi, indent='\t')
    
        # send commands via tunnel
        #with open('/purple/cmd.txt', 'r') as fi:
        #    cmds = [cmd.strip() for cmd in fi]
        #send_commands(session_name, cmd_opts=cmds, command_count=random.randint(1,20))

        # send commands via tunnel
        with open('/purple/stats.pkl', 'rb') as fi:
            stats = pickle.load(fi)
        send_commands(session_name, 
                      snddist = stats['send'], 
                      rcvdist = stats['recv'], 
                      delaydist = stats['delay'], 
                      command_count = random.choice(stats['bursts']))

        # deconstruct tunnel
        #for _ in range(int(devices)-1):
        #    time.sleep(tunnel_down_delay())  # avoid 
        #    subprocess.run(f'tmux send-keys -t {session_name}.0 "exit" Enter', shell=True)

        time.sleep(2)   # wait 2 seconds so no traffic is cut-off

        # save tmux panel contents to file
        # TODO log sometimes cuts-off; need to investigate
        log_loc = os.path.join(results_root, 'tmux.log')
        log_cmd = f'tmux capture-pane -pS - > {log_loc}'
        subprocess.run(f'{log_cmd}', shell=True)
    
    # stepping-stone and victim hosts
    else:
        set_delay(mean=2, deviation=1) # LAN delay

        # set command alias
        alias_cmd = f"echo 'alias a=\"for ((c=1; c<n-1; c ++)); do echo -n '0'; done;\"' >> ~/.bashrc"
        subprocess.run(alias_cmd, shell=True)

        # start listeners and ports
        start_listeners()

        # start traffic capture
        subprocess.run(tcpdump_cmd, shell=True)
