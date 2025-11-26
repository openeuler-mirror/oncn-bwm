#!/bin/bash

total_bandwidth=$1
priority2_client_num=$2
priority2_limitrate=$3
priority1_client_num=$4
priority1_limitrate=$5
priority0_client_num=$6
priority0_limitrate=$7

# iperf3 test options
client_ip=$8
server_ip=$9
#client_ip=`ip a | grep 'inet .* eth0' | awk -F ' ' '{print $2}' | awk -F '/' '{print $1}'`
package_len=${10:-128KB}
connect_num=${11:-1}

sh -x process-bwm-test-egress.sh  $1 $2 $3 $4 $5 $6 $7 $8 $9 $package_len $connect_num &
sleep 0.2
sh -x process-bwm-test-ingress.sh $1 $2 $3 $4 $5 $6 $7 $9 $8 $package_len $connect_num &

