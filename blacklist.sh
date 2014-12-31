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
if ! iptables -L INPUT | grep -q ${blocklist_chain_name}; then
  iptables -I INPUT 1 -m state --state NEW,RELATED -j ${blocklist_chain_name}
fi
if ! iptables -L FORWARD | grep -q ${blocklist_chain_name}; then
  iptables -I FORWARD 1 -m state --state NEW,RELATED -j ${blocklist_chain_name}
fi                                                                 

# flush the chain referencing blacklists, they will be restored in a second
iptables -F ${blocklist_chain_name}

# create the "manual" blacklist set
set_name="manual-blacklist"
if ! ipset list | grep -q "Name: ${set_name}"; then
    ipset create "${set_name}" hash:net
fi
iptables -A ${blocklist_chain_name} -m set --match-set "${set_name}" src,dst -m limit --limit 10/minute -j LOG --log-prefix "BLOCK ${set_name} "
iptables -A ${blocklist_chain_name} -m set --match-set "${set_name}" src,dst -j DROP
                                                                      
# now process the dynamic blacklists
for url in $urls; do
    # initialize temp files
    unsorted_blocklist=$(mktemp)
    sorted_blocklist=$(mktemp)
    new_set_file=$(mktemp)

    # download the blocklist
    set_name=$(basename $url)
    curl -s --compressed -k "$url" >"${unsorted_blocklist}"
    sort -u <"${unsorted_blocklist}" | egrep "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" >"${sorted_blocklist}"

    # calculate performance parameters for the new set
    tmp_set_name="tmp_${RANDOM}"
    new_list_size=$(wc -l "${sorted_blocklist}" | awk '{print $1;}' )
    hash_size=$(expr $new_list_size / 2)

    if ! ipset -q list ${set_name} >/dev/null ; then
        ipset create ${set_name} hash:net family inet
    fi

    # start writing new set file
    echo "create ${tmp_set_name} hash:net family inet hashsize ${hash_size} maxelem ${new_list_size}" >>"${new_set_file}"

    # convert list of IPs to ipset statements
    while read line; do
        echo "add ${tmp_set_name} ${line}" >>"${new_set_file}"
    done <"$sorted_blocklist"

    # replace old set with the new, temp one - this guarantees an atomic update
    echo "swap ${tmp_set_name} ${set_name}" >>"${new_set_file}"

    # clear old set (now under temp name)
    echo "destroy ${tmp_set_name}" >>"${new_set_file}"

    # actually execute the set update
    ipset -! -q restore < "${new_set_file}"

    iptables -A ${blocklist_chain_name} -m set --match-set "${set_name}" src,dst -m limit --limit 10/minute -j LOG --log-prefix "BLOCK ${set_name} "
    iptables -A ${blocklist_chain_name} -m set --match-set "${set_name}" src,dst -j DROP

    # clean up temp files
    rm "${unsorted_blocklist}" "${sorted_blocklist}" "${new_set_file}"
done


