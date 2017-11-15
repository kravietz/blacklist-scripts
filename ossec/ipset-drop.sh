#!/bin/sh

# Block an IP using Linux ipset - utility script for OSSEC active response
# Expect: srcip
# Author: Pawel Krawczyk
# Last modified: 31 Dec 2014

ACTION=$1
USER=$2
IP=$3

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)
IPSET=$(which ipset)
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
    ${IPSET} -! add ${BLACKLIST} ${IP}
elif [ "x${ACTION}" = "xdelete" ]; then
    ${IPSET} -! del ${BLACKLIST} ${IP}

# Invalid action
else
   echo "$0: invalid action: ${ACTION}"
fi

exit 1
