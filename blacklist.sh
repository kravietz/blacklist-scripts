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

if [ -z "$(which ipset)" ]; then
    echo "Cannot find ipset"
    echo "Run \"apt-get install ipset\" or \"yum install ipset\""
    exit 1
fi

if [ -z "$(which curl)" ]; then
    echo "Cannot find curl"
    echo "Run \"apt-get install curl\" or \"yum install curl\""
    exit 1
fi

# create main blocklists chain
if ! iptables -L | grep -q "Chain ${blocklist_chain_name}"; then
    iptables -N ${blocklist_chain_name}
fi

# inject references to blocklist in the beginning of input and forward chains
if ! iptables -L INPUT|grep -q ${blocklist_chain_name}; then
  iptables -I INPUT 1 -m state --state NEW,RELATED -j ${blocklist_chain_name}
fi
if ! iptables -L FORWARD|grep -q ${blocklist_chain_name}; then
  iptables -I FORWARD 1 -m state --state NEW,RELATED -j ${blocklist_chain_name}
fi                                                                 

iptables -F ${blocklist_chain_name}
                                                                      
for url in $urls; do
    # initialize temp files
    raw_blocklist=$(mktemp)
    sorted_blocklist=$(mktemp)
    new_set_file=$(mktemp)

    # download the blocklist
    set_name=$(basename $url)
    curl -s --compressed -k "$url" >"${unsorted_blocklist}"
    sort -u <"${unsorted_blocklist}" | egrep "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" >"${sorted_blocklist}"

    # calculate performance parameters for the new set
    tmp_set_name="${set_name}_tmp"
    new_list_size=$(wc -l "${sorted_blocklist}")
    hash_size=$(expr $new_list_size / 2)

    # start writing new set file
    echo "destroy ${tmp_set_name}" >>"${new_set_file}" # clean up any left overs
    echo "create ${tmp_set_name} hash:net family inet hashsize ${hash_size} maxelem ${new_list_size}" >>"${new_set_file}"

    # convert list of IPs to ipset statements
    while read line; do
        echo "add ${tmp_set_name} ${line}" >>"${new_set_file}"
    done <"$sorted_blocklist"

    echo "swap ${tmp_set_name} ${set_name}" >>"${new_set_file}" # insert new blocklist into the old set
    echo "destroy ${tmp_set_name}" >>"${new_set_file}" # remove old set

    # actually execute the set update
    ipset restore < "${new_set_file}"

    iptables -A ${blocklist_chain_name} -m set --match-set "${set_name}" src,dst -m limit --limit 10/minute -j LOG --log-prefix "BLOCK ${set_name} "
    iptables -A ${blocklist_chain_name} -m set --match-set "${set_name}" src,dst -j DROP

    # clean up temp files
    rm "${raw_blocklist}" "${sorted_blocklist}" "${new_set_file}"
done


