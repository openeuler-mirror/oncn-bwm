# 使用容器测试
在虚拟机启动两个iperf3容器: 
iperf1 端口转发 5201->15201
    docker run -itd -p 15201:5201 --name iperf1 iperf3-local bash
    docker start iperf1
    docker exec -it iperf1 bash
    iperf3 -s
iperf2 端口转发 5201->25201
    docker run -itd -p 25201:5201 --name iperf2 iperf3-local bash
    docker start iperf2
    docker exec -it iperf2 bash
    iperf3 -s

// 限制容器宿主网卡速率为总带宽：tc qdisc replace dev eth0 root tbf rate 1048576000bit burst 48kbit latency 500ms

# 测试逻辑

配置参数
ls /sys/fs/cgroup/net_cls/docker
docker ps -a
对照可得，容器id对应的UID
修改config.json

查看所有容器的PID
sudo ./main -ln
Extracted PIDs: [1 4513 4653]

给容器挂载ebpf
sudo ./main -e 4513
sudo ./main -e 4653

sudo ./main -sq 1000 // 设置网卡总出口速度 tc
sudo ./main -a 100   // 从config文件配置ebpf map
sudo ./main -a 100_run // 设置并run daemonProc

在另一台虚拟机上打流：
    iperf3 -c 192.168.56.3 -p 15201 -R  // 从宿主机向虚拟机打流，出向有200Mbps
    

删除bpf map
sudo bpftool map show
sudo rm /sys/fs/bpf/tc/globals/throttle_cfg_map

systemctl restart docker

设置本地拥塞算法为bbr：测试场景cubic受burst影响波动太大
sudo modprobe tcp_bbr
sudo sysctl net.ipv4.tcp_congestion_control
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr

