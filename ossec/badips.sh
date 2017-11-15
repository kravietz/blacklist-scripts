#!/bin/sh
# Report SSH scanners to badips
# Expect: srcip
# Author: Pawel Krawczyk
# Last modified: 15/11/2017

ACTION=$1
USER=$2
IP=$3
BADIPS_KEY=GET YOURS ON www.badips.com

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`


# Logging the call
echo "`date` $0 $1 $2 $3 $4 $5" >> ${PWD}/../logs/active-responses.log


# IP Address must be provided
if [ "x${IP}" = "x" ]; then
   echo "$0: Missing argument <action> <user> (ip)" 
   exit 1;
fi


if [ "x${ACTION}" = "xadd" ]; then
    curl -s -o /dev/null "https://www.badips.com/add/ssh/${IP}?key=${BADIPS_KEY}"
# Invalid action   
else
   echo "$0: invalid action: ${ACTION}"
fi

exit 1;
