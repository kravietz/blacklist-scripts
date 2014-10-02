#!/bin/sh

# IP blacklisting script for Linux servers
# Pawel Krawczyk https://keybase.io/kravietz
#
# This script should be installed as /etc/cron.daily/blacklist


# Emerging Threats lists offensive IPs such as botnet command servers
urls="http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
# Blocklist.de collects reports from fail2ban probes, listing password brute-forces, scanners and other offenders
urls="$urls https://www.blocklist.de/downloads/export-ips_all.txt"

blocklist_chain_name=blocklists

if [ $(which ipset) ]; then
    echo "Cannot find ipset"
    echo "Run \"apt-get install ipset\" or \"yum install ipset\""
    exit 1
fi

if [ $(which curl) ]; then
    echo "Cannot find curl"
    echo "Run \"apt-get install curl\" or \"yum install curl\""
    exit 1
fi

# create main blocklists chain
if ! iptables -L ${blocklist_chain_name}; then iptables -N ${blocklist_chain_name}; fi

# inject references to blocklist in the beginning of input and forward chains
if ! iptables -L INPUT|grep -q ${blocklist_chain_name}; then
  iptables -I INPUT 1 -m state --state NEW,RELATED -j ${blocklist_chain_name}
fi
if ! iptables -L FORWARD|grep -q ${blocklist_chain_name}; then
  iptables -I FORWARD 1 -m state --state NEW,RELATED -j ${blocklist_chain_name}
fi                                                                 

iptables -F ${blocklist_chain_name}
                                                                      
for url in $urls; do
    tmp=$(mktemp)
    tmp2=$(mktemp)
    set_name=$(basename $url)
    curl --compressed -k "$url" >"$tmp"
    sort -u <"$tmp" | egrep "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" >"$tmp2"
    ipset -! create ${set_name} hash:net
    while read line; do
        ipset add ${set_name} "$line"
    done <"$tmp2"
    iptables -A ${blocklist_chain_name} -m set --match-set "${set_name}" src,dst -m limit --limit 10/minute -j LOG --log-prefix "BLOCK ${set_name} "
    iptables -A ${blocklist_chain_name} -m set --match-set "${set_name}" src,dst -j DROP
    echo ${set_name} $(ipset list ${set_name} | wc -l)
done

