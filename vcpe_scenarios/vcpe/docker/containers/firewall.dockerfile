FROM 	alpine:latest

RUN		\
		apk --update add coreutils nano iptables tcpdump sudo

COPY 	iprules /iprules
#COPY	interfaces /etc/network/interfaces
#COPY 	script_fw.sh /script_fw.sh
#RUN	chmod +x iprules
CMD 	/iprules && tail -F /dev/null
