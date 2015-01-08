#!/bin/sh

# Block an IP using Linux ipset on a remoter router
# Utility script for OSSEC active response
# Expect: srcip
# Author: Pawel Krawczyk

# THIS MUST BE CONFIGURED
ROUTER=root@gw.example.com

# You also need to add SSH keys to the root account
# on OSSEC server (active response scripts are run
# as root) that will allow root login to the destination
# router.

ACTION=$1
USER=$2
IP=$3

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)
BLACKLIST=manual-blacklist

# Logging the call
echo "`date` $0 $1 $2 $3 $4 $5" >> ${PWD}/../logs/active-responses.log


# IP Address must be provided
if [ "x${IP}" = "x" ]; then
   echo "$0: Missing argument <action> <user> (ip)"
   exit 1;
fi

# Use ipset to handle the IP 
if [ "x${ACTION}" = "xadd" ]; then
    ssh ${ROUTER} ipset -! add ${BLACKLIST} ${IP}
elif [ "x${ACTION}" = "xdelete" ]; then
    ssh ${ROUTER} ipset -! del ${BLACKLIST} ${IP}

# Invalid action
else
   echo "$0: invalid action: ${ACTION}"
fi

exit 1
