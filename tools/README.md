# 1.简介
bwm_monitor.bt工具用于监测online/offline类型业务的实时带宽，监测的时间粒度为ms。
输出online/offline代表间隔时间内的在线流量总和/离线流量总和。
CTRL+C结束检测

# 2.使用
1）安装bpftrace
2）安装kernel-devel
3）执行./bwm_monitor.bt

# 3.参数调整
可以通过调用时传参或直接修改bwm_monitor.bt文件的一些变量修改参数：
## 1）调用时添加参数
最多添加4个参数，eg：

./bwm_monitor.bt 20971520 1073741824 10 25
./bwm_monitor.bt 30971520 0
分别表示离线业务最低带宽（bytes）离线业务最高带宽（bytes），计算平均周期的最小间隔时间(ms)，输出带宽的最小时间间隔(ms)。
输出的最小间隔 < 计算的最小间隔时，会按计算的最小间隔输出
填0或不填或填负数，会采用默认配置。

也可以不添加参数，eg：

./bwm_monitor.bt
不添加参数的时候，采取默认配置：离线业务最低带宽20971520（bytes），离线业务最高带宽1073741824（bytes），
计算平均周期的最小间隔时间10ms，输出带宽的最小时间间隔25ms

## 2）通过修改bwm_monitor.bt文件的变量来调整监测的行为
具体可调节的参数如下：

sample_interval     计算平均周期的最小间隔时间(ms)
monitor_interval    输出带宽的最小时间间隔(ms)
high_threshold      离线流量低于此门限即打印[limiting]
bandwidth_low, bandwidth_high      离线流量在此范围即打印[offline_exists]

