blacklist-scripts
=================
This is a collection of shell scripts that are intended to block Linux systems and OpenWRT routers from known sources of malicious traffic. These scripts use `iptables` with highly efficient `ipset` module to check incoming traffic against blacklists populated from publicly available sources.

## Block lists

* [Emerging Threats](http://rules.emergingthreats.net/fwrules/) - list of other known threats (botnet C&C, compromised servers etc) compiled from various sources, including [Spamhaus DROP](http://www.spamhaus.org/drop/), [Shadoserver](https://www.shadowserver.org/wiki/) and [DShield Top Attackers](http://www.dshield.org/top10.html)
* [www.blocklist.de](https://www.blocklist.de/en/index.html) - list of known password bruteforcers supplied by a network of [fail2ban](http://www.fail2ban.org/wiki/index.php/Main_Page) users
* [iBlocklist](https://www.iblocklist.com/lists.php) - various free and subscription based lists
* [Bogons](http://www.team-cymru.org/Services/Bogons/) - IP subnets that should never appear on public Internet; this includes RFC 1918 networks, so be careful with deploying in private networks

## firewall.user
This scripts is indended for OpenWRT routers. It will use the following blocklists by default:

* www.blocklist.de
* Emerging Threats
* Bogons

As it includes Bogons, it only checks incoming traffic on the WAN interface of the router. Obviously, if your WAN interface is on RFC 1918 network, you might lose connectivity from that side.

Requirements:

* `opkg install ipset curl`

Installation:

    sh firewall.user
    cp firewall.user /etc/firewall.user
    echo "01 01 * * * sh /etc/firewall.user" >>/etc/crontabs/root

Results:

    # iptables -vnL
    Chain blocklists (2 references)
     pkts bytes target     prot opt in     out     source               destination         
        0     0 LOG        all  --  eth0.2 *       0.0.0.0/0            0.0.0.0/0           match-set emerging-Block-IPs.txt src,dst limit: avg 10/min burst 5 LOG flags 0 level 4 prefix `BLOCK emerging-Block-IPs.txt ' 
        0     0 DROP       all  --  eth0.2 *       0.0.0.0/0            0.0.0.0/0           match-set emerging-Block-IPs.txt src,dst 
        0     0 LOG        all  --  eth0.2 *       0.0.0.0/0            0.0.0.0/0           match-set fullbogons-ipv4.txt src,dst limit: avg 10/min burst 5 LOG flags 0 level 4 prefix `BLOCK fullbogons-ipv4.txt ' 
        0     0 DROP       all  --  eth0.2 *       0.0.0.0/0            0.0.0.0/0           match-set fullbogons-ipv4.txt src,dst 
        6   783 LOG        all  --  eth0.2 *       0.0.0.0/0            0.0.0.0/0           match-set export-ips_all.txt src,dst limit: avg 10/min burst 5 LOG flags 0 level 4 prefix `BLOCK export-ips_all.txt ' 
        6   783 DROP       all  --  eth0.2 *       0.0.0.0/0            0.0.0.0/0           match-set export-ips_all.txt src,dst 
 
    Chain forward (1 references)
     pkts bytes target     prot opt in     out     source               destination         
     14994 1753K blocklists  all  --  *      *       0.0.0.0/0            0.0.0.0/0           state NEW,RELATED 
     ...

    Chain input (1 references)
     pkts bytes target     prot opt in     out     source               destination         
      250 13802 blocklists  all  --  *      *       0.0.0.0/0            0.0.0.0/0           state NEW,RELATED
      ...

    # ipset list | wc -l
    21553

## blacklist.sh

This script is intended for Linux servers. It does not load Bogons blocklist which can cause serious problems in VPS environments. Blacklists used:

* www.blocklist.de
* Emerging Threats

Requirements:

* On Debian, Ubuntu and other `apt` systems: `apt-get install ipset curl`
* On RedHat, Fedora, CentOS and other RPM systems: `yum install ipset curl`

Installation:

    sh blacklist.sh
    cp blacklist.sh /etc/cron.daily/blacklist

Results:

    # iptables -vnL
    Chain INPUT (policy ACCEPT 40M packets, 159G bytes)
     pkts bytes target     prot opt in     out     source               destination         
    5622K  350M blacklist  all  --  *      *       0.0.0.0/0            0.0.0.0/0           state NEW 
    
    Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
     pkts bytes target     prot opt in     out     source               destination         
    
    Chain OUTPUT (policy ACCEPT 39M packets, 166G bytes)
     pkts bytes target     prot opt in     out     source               destination         
    
    Chain blacklist (1 references)
     pkts bytes target     prot opt in     out     source               destination         
       11   488 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0           match-set blacklist src limit: avg 1/min burst 5 LOG flags 0 level 4 prefix `BLACKLIST ' 
       11   488 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0           match-set blacklist src

   # ipset list | wc -l
   22590

   # ipset list | head
   Name: blacklist
   Type: hash:net
   Header: family inet hashsize 8192 maxelem 65536 
   Size in memory: 416688
   References: 2
   Members:
   183.141.72.28
   201.210.28.205
   222.186.56.11
   178.137.16.203

   # dmesg|tail
   BLACKLIST IN=eth0 OUT= MAC=00:50:56:a0:11:61:44:d3:ca:0f:20:b7:08:00 SRC=61.174.51.198 DST=192.168.100.8 LEN=40 TOS=0x00 PREC=0x00 TTL=102 ID=256 PROTO=TCP SPT=6000 DPT=22 WINDOW=16384 RES=0x00 SYN URGP=0 
   BLACKLIST IN=eth0 OUT= MAC=00:50:56:a0:11:61:44:d3:ca:0f:20:b7:08:00 SRC=141.212.121.232 DST=192.168.100.8 LEN=40 TOS=0x00 PREC=0x00 TTL=232 ID=54321 PROTO=TCP SPT=51441 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0 
   BLACKLIST IN=eth0 OUT= MAC=00:50:56:a0:11:61:44:d3:ca:0f:20:b7:08:00 SRC=58.241.61.162 DST=192.168.100.8 LEN=48 TOS=0x00 PREC=0x00 TTL=111 ID=17539 PROTO=TCP SPT=4127 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0 
   BLACKLIST IN=eth0 OUT= MAC=00:50:56:a0:11:61:44:d3:ca:0f:20:b7:08:00 SRC=122.225.109.116 DST=192.168.100.8 LEN=40 TOS=0x00 PREC=0x00 TTL=102 ID=256 PROTO=TCP SPT=6000 DPT=22 WINDOW=16384 RES=0x00 SYN URGP=0 
   BLACKLIST IN=eth0 OUT= MAC=00:50:56:a0:11:61:44:d3:ca:0f:20:b7:08:00 SRC=122.225.103.78 DST=192.168.100.8 LEN=40 TOS=0x00 PREC=0x00 TTL=102 ID=256 PROTO=TCP SPT=6000 DPT=22 WINDOW=16384 RES=0x00 SYN URGP=0 
   BLACKLIST IN=eth0 OUT= MAC=00:50:56:a0:11:61:44:d3:ca:0f:20:b7:08:00 SRC=122.225.109.115 DST=192.168.100.8 LEN=40 TOS=0x00 PREC=0x00 TTL=102 ID=256 PROTO=TCP SPT=6000 DPT=22 WINDOW=16384 RES=0x00 SYN URGP=0 
   BLACKLIST IN=eth0 OUT= MAC=00:50:56:a0:11:61:44:d3:ca:0f:20:b7:08:00 SRC=122.225.109.208 DST=192.168.100.8 LEN=40 TOS=0x00 PREC=0x00 TTL=102 ID=256 PROTO=TCP SPT=6000 DPT=22 WINDOW=16384 RES=0x00 SYN URGP=0 
   BLACKLIST IN=eth0 OUT= MAC=00:50:56:a0:11:61:44:d3:ca:0f:20:b7:08:00 SRC=61.174.51.200 DST=192.168.100.8 LEN=40 TOS=0x00 PREC=0x00 TTL=102 ID=256 PROTO=TCP SPT=6000 DPT=22 WINDOW=16384 RES=0x00 SYN URGP=0 
   BLACKLIST IN=eth0 OUT= MAC=00:50:56:a0:11:61:44:d3:ca:0f:20:b7:08:00 SRC=198.71.58.200 DST=192.168.100.8 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=52934 DF PROTO=TCP SPT=59939 DPT=22 WINDOW=14600 RES=0x00 SYN URGP=0 
   BLACKLIST IN=eth0 OUT= MAC=00:50:56:a0:11:61:44:d3:ca:0f:20:b7:08:00 SRC=198.71.58.200 DST=192.168.100.8 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=52935 DF PROTO=TCP SPT=59939 DPT=22 WINDOW=14600 RES=0x00 SYN URGP=0
