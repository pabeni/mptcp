#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

capture=false
ksft_skip=4

usage() {
	echo "Usage: $0 [ -a ]"
	echo -e "\t-c: capture packets for each test using tcpdump (default: no capture)"
}


while getopts "$optstring" option;do
	case "$option" in
	"h")
		usage $0
		exit 0
		;;
	"c")
		capture=true
		;;
	"?")
		usage $0
		exit 1
		;;
	esac
done

sec=$(date +%s)
rndh=$(printf %x $sec)-$(mktemp -u XXXXXX)
ns1="ns1-$rndh"
ns2="ns2-$rndh"
ret=0

cleanup()
{
	for netns in "$ns1" "$ns2";do
		ip netns del $netns
	done
}

ip -Version > /dev/null 2>&1
if [ $? -ne 0 ];then
	echo "SKIP: Could not run test without ip tool"
	exit $ksft_skip
fi

trap cleanup EXIT

for i in "$ns1" "$ns2";do
	ip netns add $i || exit $ksft_skip
	ip -net $i link set lo up
	ip netns exec $i sysctl -q net.mptcp.enabled=1
done

#  "$ns1"              ns2
#    ns1eth1    ns2eth1
#    ns1eth2    ns2eth2
#    ns1eth3    ns2eth3

for i in `seq 1 3`; do
	ip link add ns1eth$i netns "$ns1" type veth peer name ns2eth$i netns "$ns2"
	ip -net "$ns1" addr add 10.0.$i.1/24 dev ns1eth$i
	ip -net "$ns1" addr add dead:beef:$i::1/64 dev ns1eth$i nodad
	ip -net "$ns1" link set ns1eth$i up

	ip -net "$ns2" addr add 10.0.$i.2/24 dev ns2eth$i
	ip -net "$ns2" addr add dead:beef:$i::2/64 dev ns2eth$i nodad
	ip -net "$ns2" link set ns2eth$i up
done

check()
{
	local cmd="$1"
	local expected="$2"
	local msg="$3"
	local out=`$cmd`

	printf "%-50s %s" "$msg"
	if [ "$out" = "$expected" ]; then
		echo "[ OK ]"
	else
		echo -n "[FAIL] "
		echo "expected '$expected' got '$out'"
		[ $ret -lt 127 ] && ret=$((ret + 1))
	fi
}

check "ip netns exec $ns1 ./pm_nl_ctl dump" "" "defaults"

ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.1
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.2 flags subflow
ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.3 flags signal
check "ip netns exec $ns1 ./pm_nl_ctl get 1" "id 1 flags  10.0.1.1 " "simple add/get"

check "ip netns exec $ns1 ./pm_nl_ctl dump" \
"id 1 flags  10.0.1.1 
id 2 flags subflow 10.0.1.2 
id 3 flags signal 10.0.1.3 " "dump"

ip netns exec $ns1 ./pm_nl_ctl del 2
check "ip netns exec $ns1 ./pm_nl_ctl get 2" "" "simple del"
check "ip netns exec $ns1 ./pm_nl_ctl dump" \
"id 1 flags  10.0.1.1 
id 3 flags signal 10.0.1.3 " "dump after del"

ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.4 id 10 flags signal
check "ip netns exec $ns1 ./pm_nl_ctl get 4" "id 4 flags signal 10.0.1.4 " "id increment"

for i in `seq 5 9`; do
	ip netns exec $ns1 ./pm_nl_ctl add 10.0.1.$i flags signal >/dev/null 2>&1
done
check "ip netns exec $ns1 ./pm_nl_ctl get 9" "id 9 flags signal 10.0.1.9 " "hard addr limit"
check "ip netns exec $ns1 ./pm_nl_ctl get 10" "" "hard addr limit "

for i in `seq 9 256`; do
	ip netns exec $ns1 ./pm_nl_ctl del $i
	ip netns exec $ns1 ./pm_nl_ctl add 10.0.0.9 >/dev/null 2>&1
done
check "ip netns exec $ns1 ./pm_nl_ctl dump" "id 1 flags  10.0.1.1 
id 3 flags signal 10.0.1.3 
id 4 flags signal 10.0.1.4 
id 5 flags signal 10.0.1.5 
id 6 flags signal 10.0.1.6 
id 7 flags signal 10.0.1.7 
id 8 flags signal 10.0.1.8 " "id limit"

exit $ret
