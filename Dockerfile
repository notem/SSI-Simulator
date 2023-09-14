# ubuntu Dockerfile
FROM ubuntu

RUN apt update && apt install iproute2 sudo python3 coreutils tcpdump vim tmux tmuxinator pip docker net-tools -y
RUN apt install netcat ncat socat openssh-server sshpass -y
RUN pip install paramiko pexpect
# ---------user configuration
RUN echo 'root:password' | chpasswd
RUN passwd -d root

# ---------listening ports
EXPOSE 22
EXPOSE 80

# --------ssh session configuration
RUN mkdir ~/.ssh
RUN chmod 700 ~/.ssh
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
RUN sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/g' /etc/ssh/sshd_config
RUN echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config
RUN touch ~/.ssh/authorized_keys
COPY config /root/.ssh/
RUN chmod 600 ~/.ssh/config
RUN service ssh start
RUN echo 'alias a="for ((c=1; c<n-2; c ++)); do echo -n '0'; done; echo -n '\n';"' >> ~/.bashrc

# --------docker-external.sh 
COPY internal.py /opt/
RUN chmod +x /opt/internal.py
COPY cmd.txt /opt/
