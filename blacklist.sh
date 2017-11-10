#!/bin/sh

# IP blacklisting script for Linux servers
# Pawel Krawczyk 2014-2015
# documentation https://github.com/kravietz/blacklist-scripts

# iptables logging limit
LIMIT="10/minute"

# try to load config file
# it should contain one blacklist URL per line

config_file="/etc/ip-blacklist.conf"
if [ -f "${config_file}" ]; then
    source ${config_file}
else
    # if no config file is available, load default set of blacklists
    # URLs for further blocklists are appended using the classical
    # shell syntax:  "$URLS new_url"

    # Emerging Threats lists offensive IPs such as botnet command servers
    URLS="http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"

    # Blocklist.de collects reports from fail2ban probes, listing password brute-forces, scanners and other offenders
    URLS="$URLS https://www.blocklist.de/downloads/export-ips_all.txt"

    # badips.com, from score 2 up
    URLS="$URLS http://www.badips.com/get/list/ssh/2"

    # iblocklist.com is also supported
    # URLS="$URLS http://list.iblocklist.com/?list=srzondksmjuwsvmgdbhi&fileformat=p2p&archiveformat=gz&username=USERNAMEx$&pin=PIN"
fi

link_set () {
    if [ "$3" = "log" ]; then
        iptables -A "$1" -m set --match-set "$2" src,dst -m limit --limit "$LIMIT" -j LOG --log-prefix "BLOCK $2 "
    fi
    iptables -A "$1" -m set --match-set "$2" src -j DROP
    iptables -A "$1" -m set --match-set "$2" dst -j DROP
}

# This is how it will look like on the server

# Chain blocklists (2 references)
#  pkts bytes target     prot opt in     out     source               destination         
#     0     0 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set manual-blacklist src,dst limit: avg 10/min burst 5 LOG flags 0 level 4 prefix "BLOCK manual-blacklist "
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set manual-blacklist src,dst
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set rules.emergingthreats src
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set rules.emergingthreats dst
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set www.blocklist.de src
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set www.blocklist.de dst
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set www.badips.com src
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set www.badips.com dst
blocklist_chain_name=blocklists

# check for dependencies - ipset and curl
if [ -z "$(which ipset 2>/dev/null)" ]; then
    echo "Cannot find ipset"
    echo "Run \"apt-get install ipset\" (Debian/Ubuntu) or \"yum install ipset\" (RedHat/CentOS/Fedora) or \"opkg install ipset\" (OpenWRT/LEDE)"
    exit 1
fi
if [ -z "$(which curl 2>/dev/null)" ]; then
    echo "Cannot find curl"
    echo "Run \"apt-get install curl\" (Debian/Ubuntu) or \"yum install curl\" (RedHat/CentOS/Fedora) or \"opkg install curl\" (OpenWRT/LEDE)"
    exit 1
fi

# check if we are on OpenWRT
if [ "$(which uci 2>/dev/null)" ]; then
    # we're on OpenWRT
    wan_iface=$(uci get network.wan.ifname)
    IN_OPT="-i $wan_iface"
    INPUT=input_rule
    FORWARD=forwarding_rule
    COMPRESS_OPT=""
else
    COMPRESS_OPT="--compressed"
    INPUT=INPUT
    FORWARD=FORWARD
fi

# create main blocklists chain
if ! iptables -nL | grep -q "Chain ${blocklist_chain_name}"; then
    iptables -N ${blocklist_chain_name}
fi

# inject references to blocklist in the beginning of input and forward chains
if ! iptables -nL ${INPUT} | grep -q ${blocklist_chain_name}; then
  iptables -I ${INPUT} 1 ${IN_OPT} -j ${blocklist_chain_name}
fi
if ! iptables -nL ${FORWARD} | grep -q ${blocklist_chain_name}; then
  iptables -I ${FORWARD} 1 ${IN_OPT} -j ${blocklist_chain_name}
fi                                                                 

# flush the chain referencing blacklists, they will be restored in a second
iptables -F ${blocklist_chain_name}

# create the "manual" blacklist set
# this can be populated manually using ipset command:
# ipset add manual-blacklist a.b.c.d
set_name="manual-blacklist"
if ! ipset list | grep -q "Name: ${set_name}"; then
    ipset create "${set_name}" hash:net
fi
link_set "${blocklist_chain_name}" "${set_name}" "$1"

# download and process the dynamic blacklists
for url in $URLS
do
    # initialize temp files
    unsorted_blocklist=$(mktemp)
    sorted_blocklist=$(mktemp)
    new_set_file=$(mktemp)
    headers=$(mktemp)

    # download the blocklist
    set_name=$(echo "$url" | awk -F/ '{print substr($3,0,21);}') # set name is derived from source URL hostname
    curl -L -v -s ${COMPRESS_OPT} -k "$url" >"${unsorted_blocklist}" 2>"${headers}"

    # this is required for blocklist.de that sends compressed content regardless of asked or not
    if [ -z "$COMPRESS_OPT" ]; then
        if grep -qi 'content-encoding: gzip' "${headers}"; then
            mv "${unsorted_blocklist}" "${unsorted_blocklist}.gz"
            gzip -d "${unsorted_blocklist}.gz"
        fi
    fi
    # autodetect iblocklist.com format as it needs additional conversion
    if echo "${url}" | grep -q 'iblocklist.com'; then
        if [ -f /etc/range2cidr.awk ]; then
            mv "${unsorted_blocklist}" "${unsorted_blocklist}.gz"
            gzip -d "${unsorted_blocklist}.gz"
            awk_tmp=$(mktemp)
            awk -f /etc/range2cidr.awk <"${unsorted_blocklist}" >"${awk_tmp}"
            mv "${awk_tmp}" "${unsorted_blocklist}"
        else
            echo "/etc/range2cidr.awk script not found, cannot process ${unsorted_blocklist}, skipping"
            continue
        fi
    fi

    sort -u <"${unsorted_blocklist}" | egrep "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$" >"${sorted_blocklist}"

    # calculate performance parameters for the new set
    if [ "${RANDOM}" ]; then
        # bash
        tmp_set_name="tmp_${RANDOM}"
    else
        # non-bash
        tmp_set_name="tmp_$$"
    fi
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
    
    link_set "${blocklist_chain_name}" "${set_name}" "$1"

    # clean up temp files
    rm "${unsorted_blocklist}" "${sorted_blocklist}" "${new_set_file}" "${headers}"
done
