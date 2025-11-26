#!/bin/bash

time=$(date "+%Y%m%d%H%M%S")
test_time=60

# bwm setting
total_bandwidth=$(expr $1 \* 1024 \* 1024)bit
priority2_client_num=$2
priority2_limitrate=$3
priority1_client_num=$4
priority1_limitrate=$5
priority0_client_num=$6
priority0_limitrate=$7
total_client_num=`expr $2 + $4 + $6`

# iperf3 test options
client_ip=$8
server_ip=$9
#client_ip=`ip a | grep 'inet .* eth0' | awk -F ' ' '{print $2}' | awk -F '/' '{print $1}'`
package_len=${10:-128KB}
connect_num=${11:-1}

log_path=$time-"egress"-$1"Mb"-$priority2_client_num-$priority2_limitrate"Mb"-$priority1_client_num-$priority1_limitrate$"Mb"-$priority0_client_num-0-$client_ip-$server_ip-$package_len-$connect_num
mkdir -p $log_path

# for host process, tc operation will make the ebpf prog in host interface ineffective.
#tc qdisc replace dev enp2s2 root tbf rate $total_bandwidth burst 48kbit latency 500ms
#tc qdisc replace dev eth0 root tbf rate $total_bandwidth burst 48kbit latency 500ms

port_prefix="500"

function ssh_cmd() {
    hostip=$1
    hostname=$2
    rootpwd=$3
    cmd=$4
    timeout=-1

    rm -rf /root/.ssh/known_hosts

    /usr/bin/expect << EOF
        spawn ssh ${hostname}@${hostip} "${cmd}"
        expect {
            # first connect, no public key in ~/.ssh/known_hosts
            "Are you sure you want to continue connecting*" {
                send "yes\r"
                expect "*assword:*" {
                    send "${rootpwd}\r"
                }
                expect timeout { exit 1;}
            }
        expect eof
        }
EOF
}

# start all iperf3 server on different port
index=1
while [ $index -lt `expr $total_client_num + 1` ]
do
        ssh_cmd $server_ip root Huawei12\#$ "iperf3 -s -p $port_prefix$index 2>&1 &" &
	let index++
        sleep 1
done

# priority 0 flowing test
index=1
cnt=1
while [ $index -lt `expr $priority0_client_num + 1` ]
do
	bwmctl set egress $server_ip:$port_prefix$index 0 $priority0_limitrate $1 > $log_path/priority0-$port_prefix$index-$cnt.log 2>&1 &
        iperf3 -c $server_ip -i 1 -t $test_time -p $port_prefix$index -l $package_len -P $connect_num >> $log_path/priority0-$port_prefix$index-$cnt.log 2>&1 &
        let index++
	let cnt++
	sleep 0.5
done

# priority 1 flowing test
index=`expr $priority0_client_num + 1`
cnt=1
while [ $index -lt `expr $priority0_client_num + $priority1_client_num + 1` ]
do
        bwmctl set egress $server_ip:$port_prefix$index 1 $priority1_limitrate $1 > $log_path/priority1-$port_prefix$index-$cnt.log 2>&1 &
        iperf3 -c $server_ip -i 1 -t $test_time -p $port_prefix$index -l $package_len -P $connect_num >> $log_path/priority1-$port_prefix$index-$cnt.log 2>&1 &
        let index++
	let cnt++
	sleep 0.5
done

# priority 2 flowing test
index=`expr $priority0_client_num + $priority1_client_num + 1`
cnt=1
while [ $index -lt `expr $total_client_num + 1` ]
do
	bwmctl set egress $server_ip:$port_prefix$index 2 $priority2_limitrate $1 > $log_path/priority2-$port_prefix$index-$cnt.log 2>&1 &
        iperf3 -c $server_ip -i 1 -t $test_time -p $port_prefix$index -l $package_len -P $connect_num >> $log_path/priority2-$port_prefix$index-$cnt.log 2>&1 &
        let index++
	let cnt++
	sleep 0.5
done



#bwmctl set egress 9.82.220.71:5001  0 $priority0_limitrate $1
#bwmctl set egress 9.82.169.67:5002 1 $priority1_limitrate $1
#bwmctl set egress 9.82.226.64:5003 1 $priority1_limitrate $1
#bwmctl set egress 9.82.205.115:5004  2 $priority2_limitrate $1
#iperf3 -c 9.82.220.71 -i 1 -t $test_time -p 5001 > $log_path/priority0-5001-1.log 2>&1 &
#iperf3 -c 9.82.169.67 -i 1 -t $test_time -p 5002 > $log_path/priority1-5002-1.log 2>&1 &
#iperf3 -c 9.82.226.64 -i 1 -t $test_time -p 5003 > $log_path/priority1-5003-2.log 2>&1 &
#iperf3 -c 9.82.205.115 -i 1 -t $test_time -p 5004 > $log_path/priority2-5004-1.log 2>&1 &

sleep `expr $test_time + 5`

# collect logs
cd ${log_path}
ls *.log > log_file
while read line
do
        echo "===== $line =====" >> $log_path.log
        cat $line >> $log_path.log
        echo $'\n' >> $log_path.log
        sleep 0.1
done < log_file
rm -rf log_file
cd ../

# kill all iperf3 server port
ssh_cmd $server_ip root Huawei12\#$ "pkill iperf3"
