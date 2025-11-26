#!/bin/bash

time=$(date "+%Y%m%d%H%M%S")

test_time=60

# 1000Mb=1000 * 1024 * 1024bit = 1048576000bit
total_bandwidth=$(expr $1 \* 1024 \* 1024)bit
priority2_client_num=$2
priority2_limitrate=$3
priority1_client_num=$4
priority1_limitrate=$5
priority0_client_num=$6
priority0_limitrate=$7
total_client_num=`expr $2 + $4 + $6`

package_len=${8:-128KB}
connect_num=${9:-1}

log_path=$time-"egress"-$1$"Mb"-$priority2_client_num-$priority2_limitrate-$priority1_client_num-$priority1_limitrate-$priority0_client_num-0-$package_len-$connect_num
mkdir -p $log_path

iperf3_server_yaml="egress-iperf3-server.yaml"
priority0_client_yaml="0-egress-iperf3-client.yaml"
priority1_client_yaml="1-egress-iperf3-client.yaml"
priority2_client_yaml="2-egress-iperf3-client.yaml"

#tc qdisc replace dev enp2s2 root tbf rate $total_bandwidth burst 48kbit latency 500ms
#tc qdisc replace dev eth0 root tbf rate $total_bandwidth burst 48kbit latency 500ms

sed -i 's/replicas: .*/replicas: '"$total_client_num"'/g' $iperf3_server_yaml

sed -i 's/replicas: .*/replicas: '"$priority0_client_num"'/g' $priority0_client_yaml
#sed -i 's/\("request":"\)[^"]*"/\1$priority0_limitrate"/' $priority0_client_yaml

sed -i 's/replicas: .*/replicas: '"$priority1_client_num"'/g' $priority1_client_yaml
sed -i 's/\("request":"\)[^"]*"/\1'"$priority1_limitrate"'"/' $priority1_client_yaml

sed -i 's/replicas: .*/replicas: '"$priority2_client_num"'/g' $priority2_client_yaml
sed -i 's/\("request":"\)[^"]*"/\1'"$priority2_limitrate"'"/' $priority2_client_yaml

kubectl apply -f $iperf3_server_yaml
kubectl apply -f $priority0_client_yaml
kubectl apply -f $priority1_client_yaml
kubectl apply -f $priority2_client_yaml

while [ "$iperf3_server_num" != "$total_client_num" ] || [ "$iperf3_client_num" != "$total_client_num" ] || [ $iperf3_terminating_num != "0" ]
do
  echo "Waiting for All iperf3 Pod create ..."
  iperf3_server_num=`kubectl get pods -A -owide | grep egress-iperf3-server | grep Running | wc -l`
  iperf3_client_num=`kubectl get pods -A -owide | grep egress-iperf3-client | grep Running | wc -l`
  iperf3_terminating_num=`kubectl get pods -A -owide | grep egress-iperf3 | grep Terminating | wc -l`

  sleep 1
done

echo "All iperf3 Pod create success!"

priority0_client=`kubectl get pods -A -owide | grep 0-egress-iperf3-client | awk -F ' ' '{print $2}'`
priority1_client=`kubectl get pods -A -owide | grep 1-egress-iperf3-client | awk -F ' ' '{print $2}'`
priority2_client=`kubectl get pods -A -owide | grep 2-egress-iperf3-client | awk -F ' ' '{print $2}'`
iperf3_server_ips=`kubectl get pods -A -owide | grep egress-iperf3-server | awk -F ' ' '{print $7}'`

#priority 0 flowing test
index=1
cnt=1
while [ $index -lt `expr $priority0_client_num + 1` ]
do
        client_pod_name=`echo $priority0_client | awk -F' '  '{print $'$cnt'}'`
        server_pod_ip=`echo $iperf3_server_ips | awk -F' '  '{print $'$index'}'`
        kubectl exec -it $client_pod_name -- iperf3 -c $server_pod_ip -i 1 -t $test_time -p 5201 -l $package_len -P $connect_num > $log_path/$client_pod_name-$cnt.log 2>&1 &
        let index++
        let cnt++
	sleep 0.5
done

#priority 1 flowing test
index=`expr $priority0_client_num + 1`
cnt=1
while [ $index -lt `expr $priority0_client_num + $priority1_client_num + 1` ]
do
        client_pod_name=`echo $priority1_client | awk -F' '  '{print $'$cnt'}'`
        server_pod_ip=`echo $iperf3_server_ips | awk -F' '  '{print $'$index'}'`
        kubectl exec -it $client_pod_name -- iperf3 -c $server_pod_ip -i 1 -t $test_time -p 5201 -l $package_len -P $connect_num > $log_path/$client_pod_name-$cnt.log 2>&1 &
        let index++
        let cnt++
	sleep 0.5
done

#priority 2 flowing test
index=`expr $priority0_client_num + $priority1_client_num + 1`
cnt=1
while [ $index -lt `expr $total_client_num + 1` ]
do
        client_pod_name=`echo $priority2_client | awk -F' '  '{print $'$cnt'}'`
        server_pod_ip=`echo $iperf3_server_ips | awk -F' '  '{print $'$index'}'`
        kubectl exec -it $client_pod_name -- iperf3 -c $server_pod_ip -i 1 -t $test_time -p 5201 -l $package_len -P $connect_num > $log_path/$client_pod_name-$cnt.log 2>&1 &
        let index++
        let cnt++
	sleep 0.5
done

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

# clear test pods
#kubectl delete -f $iperf3_server_yaml
#kubectl delete -f $priority0_client_yaml
#kubectl delete -f $priority1_client_yaml
#kubectl delete -f $priority2_client_yaml

