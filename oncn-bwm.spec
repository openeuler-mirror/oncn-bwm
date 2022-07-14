Name:       oncn-bwm
Version:    1.0
Release:    1
Summary:    Pod bandwidth management in mixed deployment scenarios of online and offline services
License:    GPL-2.0
URL:        https://gitee.com/src-openeuler/oncn-bwm
Source:     %{name}-%{version}.tar.gz

BuildRequires: libbpf-devel cmake gcc clang 
Requires: iproute libbpf
Requires(preun): bpftool

%description
Pod bandwidth management in mixed deployment scenarios of online and offline services

%package -n oncn-bwm-devel
Summary:    devel tools for oncn-bwm
Requires:   bpftrace

%description -n oncn-bwm-devel
devel tools for oncn-bwm

%prep
%autosetup -n %{name}-%{version} -p1

%build
mkdir build && cd build &&
cmake ..
make

%install
mkdir -p %{buildroot}/%{_bindir}/%{name}
mkdir -p %{buildroot}/usr/share/bwmcli
install -Dpm 0500 %{_builddir}/%{name}-%{version}/build/bpf/CMakeFiles/bwm_prio_kern.dir/bwm_prio_kern.c.o      %{buildroot}/usr/share/bwmcli/bwm_prio_kern.o
install -Dpm 0500 %{_builddir}/%{name}-%{version}/build/bpf/CMakeFiles/bwm_tc.dir/bwm_tc.c.o     %{buildroot}/usr/share/bwmcli/bwm_tc.o
install -Dpm 0500 %{_builddir}/%{name}-%{version}/build/bwmcli              %{buildroot}/%{_bindir}
install -Dpm 0500 %{_builddir}/%{name}-%{version}/tools/bwm_monitor.bt      %{buildroot}/%{_bindir}

%preun

DisableAllDevices()
{
    local CGROUP2PATH
    local CGROUP2ID
    local tempfile
    for NETPID in $(lsns -t net | grep net -w | awk '{print $4}'); do
        nsenter -n -t${NETPID} bwmcli -d >/dev/null
    done

    mount |grep "type cgroup2" >/dev/null
    if [ $? -ne 0 ]; then
        tempfile=`mktemp -d`;
        mount none -t cgroup2 $tempfile;
    fi

    for CGROUP2VAL in $(bpftool cgroup tree |grep _bwm_out_cg -B 1 | awk '{print $1}'); do
        if [[ $CGROUP2VAL = /* ]]; then
            CGROUP2PATH=$CGROUP2VAL >/dev/null
        else
            CGROUP2ID=$CGROUP2VAL
            bpftool cgroup detach $CGROUP2PATH egress id $CGROUP2ID >/dev/null
        fi
    done

    if [ -n "$tempfile" ]; then
        umount $tempfile
        rm -rf $tempfile
    fi

    rm -f /sys/fs/bpf/tc/globals/throttle_map >/dev/null
    rm -f /sys/fs/bpf/tc/globals/throttle_cfg >/dev/null
}

if [ $1 -eq 0 ]; then
    DisableAllDevices
fi

%files
%defattr(-,root,root)
%attr(0500,root,root) %{_bindir}/bwmcli
%attr(0500,root,root) /usr/share/bwmcli/bwm_prio_kern.o
%attr(0500,root,root) /usr/share/bwmcli/bwm_tc.o

%files -n oncn-bwm-devel
%attr(0500,root,root) %{_bindir}/bwm_monitor.bt


%changelog
* Thu Jul 14 2022 wo_cow <niuiqianqian@huawei.com> - 1.0-1
- init oncn-bwm
