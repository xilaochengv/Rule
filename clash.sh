CLASHDIR=$(dirname $0) && [ -s $CLASHDIR/config.txt ] && . $CLASHDIR/config.txt
RED='\e[0;31m';GREEN='\e[1;32m';YELLOW='\e[1;33m';BLUE='\e[1;34m';PINK='\e[1;35m';SKYBLUE='\e[1;36m';RESET='\e[0m'
sed -i '/clash=/d' /etc/profile && echo -e "\nexport CLASHDIR=$(dirname $0);alias clash=\"$0\"" >> /etc/profile && sed -i '/./,/^$/!d' /etc/profile
route=$(ip route | grep br-lan | awk {'print $1'})
routes="127.0.0.0/8 $(ip route | grep br-lan | awk {'print $1'})"
routev6=$(ip -6 route | grep br-lan | awk '{print $1}')
routesv6="::1/128 $(ip -6 route | grep br-lan | awk '{print $1}')"
localip=$(ip route | grep br-lan | awk {'print $9'})
wanipv4=$(ip -o addr | grep pppoe-wan | grep 'inet ' | awk '{print $4}')
wanipv6=$(ip -o addr | grep pppoe-wan | grep inet6.*global | sed -e 's/.*inet6 //' -e 's#/.*##')
[ ! "$convertserver" ] && convertserver=https://api.v1.mk
[ ! "$exclude" ] && exclude='节点过滤|多个关键字请用|竖线分割'
[ ! "$redir_port" ] && redir_port=25274
[ ! "$dashboard_port" ] && dashboard_port=6789
[ ! "$core_ipv6" ] && core_ipv6=关
[ ! "$dns_port" ] && dns_port=1053
[ ! "$dns_default" ] && dns_default='223.6.6.6'
[ ! "$dns_fallback" ] && dns_fallback='tls://1.0.0.1, tls://8.8.4.4'
[ ! "$mac_filter" ] && mac_filter=关
[ ! "$mac_filter_mode" ] && mac_filter_mode=黑名单
[ ! "$cnip_route" ] && cnip_route=关
[ ! "$cnipv6_route" ] && cnipv6_route=关
[ ! "$common_ports" ] && common_ports=关
[ ! "$multiports" ] && multiports=53,80,123,143,194,443,465,587,853,993,995,5222,8080,8443
[ ! "$wakeonlan_ports" ] && wakeonlan_ports=9
[ ! "$Clash_Local_Proxy" ] && Clash_Local_Proxy=关
[ -s $CLASHDIR/custom_rules.yaml ] || echo -e "#说明文档：https://wiki.metacubex.one/config/rules\n#填写格式：\n#DOMAIN,baidu.com,DRIECT（不需要填前面的-符号）" > $CLASHDIR/custom_rules.yaml
start(){
	stop start && update missingfiles
	[ "$core_ipv6" = "开" ] && ipv6=true || ipv6=false
	cat > $CLASHDIR/config.yaml << EOF
redir-port: $redir_port
allow-lan: true
authentication:
  - "username:password"
log-level: debug
ipv6: $ipv6
keep-alive-interval: 30
find-process-mode: "off"
external-controller: :$dashboard_port
external-ui: ui
profile:
  store-selected: true
unified-delay: true
geodata-mode: true
geox-url:
  geoip: "https://mirror.ghproxy.com/https://github.com/xilaochengv/Rule/releases/download/Latest/geoip.dat"
  geosite: "https://mirror.ghproxy.com/https://github.com/xilaochengv/Rule/releases/download/Latest/geosite.dat"
dns:
  enable: true
  listen: :$dns_port
  ipv6: $ipv6
  enhanced-mode: redir-host
  default-nameserver:
    - 223.6.6.6
  nameserver-policy:
    'geosite: cn': [$dns_default]
  nameserver: [$dns_fallback]
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  sniff:
    http:
      ports:
        - 80
        - 8000-8888
    tls:
      ports:
        - 443
        - 8443
    quic:
      ports:
        - 443
        - 8443
  skip-domain:
    - Mijia Cloud
tun:
  enable: true
  stack: mixed
  device: utun
  auto-route: false
  udp-timeout: 60
$(sed -n '/^proxies/,/^rules/p' $CLASHDIR/config_original.yaml | tail +1)
EOF
	sed -n '/^rules/,/*/p' $CLASHDIR/config_original.yaml | tail +2 > $CLASHDIR/rules.yaml && sed -i 's/GEOIP.*/&,no-resolve/' $CLASHDIR/rules.yaml
	LINES=$(awk -F , '{print $1","$2}' $CLASHDIR/rules.yaml | sed 's/.*- //' | awk 'a[$0]++ {print NR}')
	[ "$LINES" ] && for LINE in $(printf '%05d\n' $LINES | sort -r);do sed -i "${LINE}d" $CLASHDIR/rules.yaml;done
	spaces=$(sed -n 1p $CLASHDIR/rules.yaml | grep -oE '^ *- *')
	sed -n '/^[^#]/p' $CLASHDIR/custom_rules.yaml | sed "s/.*/$spaces&\t#自定义规则/" >> $CLASHDIR/config.yaml
	cat $CLASHDIR/rules.yaml >> $CLASHDIR/config.yaml && rm -f $CLASHDIR/rules.yaml
	error="$($CLASHDIR/mihomo -d $CLASHDIR -t $CLASHDIR/config.yaml | grep error | awk -F = '{print $3"="$NF}')"
	[ "$error" ] && echo -e "\n${BLUE}Clash-mihomo $RED启动失败！\n$RESET\n$error\n" && exit
	sed -i '/Clash/d' /etc/passwd && echo "Clash:x:0:$redir_port:::" >> /etc/passwd
	modprobe tun 2> /dev/null
	start-stop-daemon -Sbc Clash:$redir_port -x $CLASHDIR/mihomo -- -d $CLASHDIR &
	while [ ! "$(ifconfig | grep utun)" ];do usleep 100000;done
	startfirewall && date +%s > $CLASHDIR/starttime
	curl -so /dev/null "http://127.0.0.1:$dashboard_port/group/节点选择/delay?url=https://www.google.com/generate_204&timeout=5000" &
	echo -e "while [ true ];do\n\tsleep 1\n\t[ \$(awk 'NR==3{print \$2}' /proc/meminfo) -lt 102400 ] && curl -so /dev/null \"http://127.0.0.1:$dashboard_port/debug/gc\" -X PUT\ndone" > /tmp/autooc.sh && chmod 755 /tmp/autooc.sh && /tmp/autooc.sh &
	echo -e "\n${BLUE}Clash-mihomo $GREEN启动成功！$YELLOW面板管理页面：$SKYBLUE$localip:$dashboard_port/ui$RESET\n"
	#修复小米AX9000开启QOS功能情况下某些特定udp端口（如80 8080等）流量无法通过问题
	[ "$(uci get /usr/share/xiaoqiang/xiaoqiang_version.version.HARDWARE 2> /dev/null)" = "RA70" ] && [ -d /sys/module/shortcut_fe_cm ] && rmmod shortcut-fe-cm &> /dev/null
}
stop(){
	killall mihomo 2> /dev/null
	stopfirewall && rm -f $CLASHDIR/starttime
	while [ "$(ps | grep -v grep | grep autooc)" ];do killpid $(ps | grep -v grep | grep autooc | head -1 | awk '{print $1}');done
	[ ! "$1" ] && echo -e "\n${BLUE}Clash-mihomo $RED已停止服务！$RESET\n"
	#AX9000若QOS功能开启则恢复加载数据小包加速管理中心模块
	[ "$(uci get /usr/share/xiaoqiang/xiaoqiang_version.version.HARDWARE 2> /dev/null)" = "RA70" ] && [ -d /sys/module/shortcut_fe ] && insmod shortcut-fe-cm &> /dev/null
	return 0
}
saveconfig(){
	echo "sublink='$sublink'" > $CLASHDIR/config.txt
	echo "exclude='$exclude'" >> $CLASHDIR/config.txt
	echo "convertserver=$convertserver" >> $CLASHDIR/config.txt
	echo -e "\n#修改以下配置前，必须先运行脚本并选择2停止Clash-mihomo！否则修改前的防火墙规则无法清理干净！" >> $CLASHDIR/config.txt
	echo "redir_port=$redir_port" >> $CLASHDIR/config.txt
	echo -e "\n#以下配置修改后，需要重启Clash-mihomo后才能生效" >> $CLASHDIR/config.txt
	echo "dashboard_port=$dashboard_port" >> $CLASHDIR/config.txt
	echo "core_ipv6=$core_ipv6" >> $CLASHDIR/config.txt
	echo "dns_port=$dns_port" >> $CLASHDIR/config.txt
	echo "dns_default='$dns_default'" >> $CLASHDIR/config.txt
	echo "dns_fallback='$dns_fallback'" >> $CLASHDIR/config.txt
	echo -e "\n#以下配置只需要运行脚本并选择3-7即可修改" >> $CLASHDIR/config.txt
	echo "mac_filter=$mac_filter" >> $CLASHDIR/config.txt
	echo "mac_filter_mode=$mac_filter_mode" >> $CLASHDIR/config.txt
	echo "cnip_route=$cnip_route" >> $CLASHDIR/config.txt
	echo "cnipv6_route=$cnipv6_route" >> $CLASHDIR/config.txt
	echo "common_ports=$common_ports" >> $CLASHDIR/config.txt
	echo "Clash_Local_Proxy=$Clash_Local_Proxy" >> $CLASHDIR/config.txt
	echo -e "\n#以下配置修改后，需要运行脚本并选择3-7随意一项才可马上生效" >> $CLASHDIR/config.txt
	echo "multiports=$multiports" >> $CLASHDIR/config.txt
	echo "wakeonlan_ports=$wakeonlan_ports" >> $CLASHDIR/config.txt
	echo "dns_server_ip_filter='$dns_server_ip_filter'" >> $CLASHDIR/config.txt
	[ ! "$sublink" ] && echo -e "$RED请先在 $SKYBLUE$CLASHDIR/config.txt $RED文件中填写好订阅链接！$RESET" && exit
	return 0
}
download(){
	url=$4 && echo -e "$YELLOW下载$3······$RESET" && rm -f $1
	[ "$(echo $url | grep -vE '/http|=http' | grep -E 'github.com/|githubusercontent.com/')" ] && url="$(echo $url | sed 's#.*#https://mirror.ghproxy.com/&#')"
	while [ ! -f $1 ];do
		curl -m 10 -#Lko $1 "$url"
		[ -f $1 ] && [ $(wc -c < $1) -lt $2 ] && rm -f $1
	done
	echo -e "\033[32m$3下载成功！\033[0m\n"
}
update(){
	[ ! "$1" ] && stop && rm -rf $CLASHDIR/ui $CLASHDIR/cn_ip.txt $CLASHDIR/cn_ipv6.txt $CLASHDIR/config.yaml $CLASHDIR/config_original.yaml $CLASHDIR/GeoIP.dat $CLASHDIR/GeoSite.dat $CLASHDIR/mihomo
	[ ! -d $CLASHDIR/ui ] && {
		download "/tmp/dashboard" "300000" "Meta基础面板" "https://raw.githubusercontent.com/juewuy/ShellCrash/dev/bin/dashboard/meta_db.tar.gz"
		mkdir -m 755 $CLASHDIR/ui && tar -zxf /tmp/dashboard -C $CLASHDIR/ui && rm -f /tmp/dashboard
		sed -i "s/9090/$dashboard_port/g;s/127.0.0.1/$localip/g" $CLASHDIR/ui/assets/index.628acf3b.js
	}
	[ ! -f $CLASHDIR/mihomo ] && {
		while [ ! "$latestversion" ];do latestversion=$(curl --connect-timeout 3 -sk "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" | grep tag_name | cut -f4 -d '"');done
		download "/tmp/mihomo.gz" "9500000" "Clash主程序文件" "https://github.com/MetaCubeX/mihomo/releases/download/$latestversion/mihomo-linux-arm64-$latestversion.gz"
		rm -f $CLASHDIR/mihomo && gzip -d /tmp/mihomo.gz && mv -f /tmp/mihomo $CLASHDIR/mihomo && chmod 755 $CLASHDIR/mihomo
	}
	[ ! -f $CLASHDIR/config_original.yaml ] && {
		sublink=$(echo $sublink | sed 's/;/\%3B/g; s|/|\%2F|g; s/?/\%3F/g; s/:/\%3A/g; s/@/\%40/g; s/=/\%3D/g; s/&/\%26/g')
		download "$CLASHDIR/config_original.yaml" "5000" "规则文件（Clash内核）" "$convertserver/sub?target=clash&new_name=true&scv=true&udp=true&exclude=$exclude&url=$sublink&config=https://raw.githubusercontent.com/xilaochengv/Rule/main/rule.ini"
	}
	[ ! -f $CLASHDIR/cn_ip.txt -a "$cnip_route" = "开" ] && download "$CLASHDIR/cn_ip.txt" "130000" "CN-IP数据库文件" "https://github.com/xilaochengv/Rule/releases/download/Latest/cn_ip.txt"
	[ ! -f $CLASHDIR/cn_ipv6.txt -a "$core_ipv6" = "开" -a "$cnipv6_route" = "开" ] && download "$CLASHDIR/cn_ipv6.txt" "29000" "CN-IPV6数据库文件" "https://github.com/xilaochengv/Rule/releases/download/Latest/cn_ipv6.txt"
	[ ! -f $CLASHDIR/GeoIP.dat ] && download "$CLASHDIR/GeoIP.dat" "130000" "精简版GeoIP-CN数据库文件" "https://github.com/xilaochengv/Rule/releases/download/Latest/geoip.dat"
	[ ! -f $CLASHDIR/GeoSite.dat ] && download "$CLASHDIR/GeoSite.dat" "1350000" "精简版GeoSite数据库文件" "https://github.com/xilaochengv/Rule/releases/download/Latest/geosite.dat"
	[ ! "$1" ] && start
}
startfirewall(){
	stopfirewall && update missingfiles
	ip route add default dev utun table 100 2> /dev/null
	ip rule add fwmark $redir_port table 100
	[ "$core_ipv6" = "开" ] && {
		ip -6 route add default dev utun table 100 2> /dev/null
		ip -6 rule add fwmark $redir_port table 100
	}
	[ "$cnip_route" = "开" ] && echo "create cn_ip hash:net" > /tmp/cn_ip.ipset && sed 's/.*/add cn_ip &/' $CLASHDIR/cn_ip.txt >> /tmp/cn_ip.ipset && ipset -! restore < /tmp/cn_ip.ipset && rm -f /tmp/cn_ip.ipset
	[ "$core_ipv6" = "开" -a "$cnipv6_route" = "开" ] && echo "create cn_ipv6 hash:net family inet6" > /tmp/cn_ipv6.ipset && sed 's/.*/add cn_ipv6 &/' $CLASHDIR/cn_ipv6.txt >> /tmp/cn_ipv6.ipset && ipset -! restore < /tmp/cn_ipv6.ipset && rm -f /tmp/cn_ipv6.ipset
	iptables -t mangle -N Clash && iptables -t nat -N Clash
	[ "$core_ipv6" = "开" ] && ip6tables -t mangle -N Clash && ip6tables -t nat -N Clash
	if [ "$common_ports" = "开" ];then
		ports="" && amount=0 && for port in $(echo $multiports | awk -F , '{for(i=1;i<=NF;i++){print $i};}');do
			ports="$ports,$port" && let amount++
			[ $amount == 15 ] && {
				ports=$(echo $ports | sed 's/^,//')
				iptables -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
				iptables -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
				[ "$core_ipv6" = "开" ] && {
					ip6tables -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
					ip6tables -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
				}
				amount=0 && ports=""
			}
		done
		[ "$ports" ] && {
			ports=$(echo $ports | sed 's/^,//')
			iptables -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
			iptables -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
			[ "$core_ipv6" = "开" ] && {
				ip6tables -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
				ip6tables -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
			}
		}
	else
		iptables -t mangle -A PREROUTING -p udp -m comment --comment "udp流量进入Clash规则链" -j Clash
		iptables -t nat -A PREROUTING -p tcp -m comment --comment "tcp流量进入Clash规则链" -j Clash
		[ "$core_ipv6" = "开" ] && {
			ip6tables -t mangle -A PREROUTING -p udp -m comment --comment "udp流量进入Clash规则链" -j Clash
			ip6tables -t nat -A PREROUTING -p tcp -m comment --comment "tcp流量进入Clash规则链" -j Clash
		}
	fi
	iptables -I FORWARD -o utun -p udp -m comment --comment "utun出口流量允许放行" -j ACCEPT
	[ "$core_ipv6" = "开" ] && ip6tables -I FORWARD -o utun -p udp -m comment --comment "utun出口流量允许放行" -j ACCEPT
	[ "$wanipv4" -a "$common_ports" = "关" ] && {
		iptables -t mangle -A Clash -d $wanipv4 -p udp -m multiport --dports $wakeonlan_ports -m comment --comment "udp流量目标地址和端口分别为本地WAN口IPv4地址和网络唤醒端口，直接绕过Clash内核" -j RETURN
		[ "$wanipv6" -a "$core_ipv6" = "开" ] && ip6tables -t mangle -A Clash -d $wanipv6 -p udp -m multiport --dports $wakeonlan_ports -m comment --comment "udp流量目标地址和端口分别为本地WAN口IPv4地址和网络唤醒端口，直接绕过Clash内核" -j RETURN
	}
	for ip in $routes;do
		iptables -t mangle -A Clash -d $ip -p udp -m comment --comment "udp流量目的地为本地IP网段，直接绕过Clash内核" -j RETURN
		iptables -t nat -A Clash -d $ip -p tcp -m comment --comment "tcp流量目的地为本地IP网段，直接绕过Clash内核" -j RETURN
	done
	[ "$core_ipv6" = "开" ] && {
		for ip in $routesv6;do
			ip6tables -t mangle -A Clash -d $ip -p udp -m comment --comment "udp流量目的地为本地IPv6网段，直接绕过Clash内核" -j RETURN
			ip6tables -t nat -A Clash -d $ip -p tcp -m comment --comment "tcp流量目的地为本地IPv6网段，直接绕过Clash内核" -j RETURN
		done
	}
	[ "$cnip_route" = "开" ] && {
		iptables -t mangle -A Clash -m set --match-set cn_ip dst -p udp -m comment --comment "udp流量目的地为国内IPv4地址，直接绕过Clash内核" -j RETURN
		iptables -t nat -A Clash -m set --match-set cn_ip dst -p tcp -m comment --comment "tcp流量目的地为国内IPv4地址，直接绕过Clash内核" -j RETURN
	}
	[ "$core_ipv6" = "开" -a "$cnipv6_route" = "开" ] && {
		ip6tables -t mangle -A Clash -m set --match-set cn_ipv6 dst -p udp -m comment --comment "udp流量目的地为国内IPv6地址，直接绕过Clash内核" -j RETURN
		ip6tables -t nat -A Clash -m set --match-set cn_ipv6 dst -p tcp -m comment --comment "tcp流量目的地为国内IPv6地址，直接绕过Clash内核" -j RETURN
	}
	[ "$mac_filter" = "开" ] && {
		if [ "$(grep -v '^ *#' $CLASHDIR/maclist 2> /dev/null)" ];then
			while read LINE;do
				ip=$(echo $LINE | grep -v '^ *#' | awk '{print $1}' | grep '\.')
				mac=$(echo $LINE | grep -v '^ *#' | awk '{print $1}' | grep ':')
				device=$(echo $LINE | grep -v '^ *#' | awk '{for(i=2;i<=NF;i++){printf"%s ",$i};print out}' | sed 's/ $//');[ ! "$device" ] && device=设备名称未填写
				[ "$ip" ] && [ "$ip" != "$localip" ] && {
					if [ "$mac_filter_mode" = "白名单" ];then
						iptables -t mangle -A Clash -s $ip -p udp -m comment --comment "udp流量进入Clash内核（$device）" -j MARK --set-mark $redir_port
						iptables -t nat -A Clash -s $ip -p tcp -m comment --comment "tcp流量进入Clash内核（$device）" -j REDIRECT --to-port $redir_port
						[ "$core_ipv6" = "开" ] && {
							ip6tables -t mangle -A Clash -s $ip -p udp -m comment --comment "udp流量进入Clash内核（$device）" -j MARK --set-mark $redir_port
							ip6tables -t nat -A Clash -s $ip -p tcp -m comment --comment "tcp流量进入Clash内核（$device）" -j REDIRECT --to-port $redir_port
						}
					else
						iptables -t mangle -A Clash -s $ip -p udp -m comment --comment "udp流量禁止进入Clash内核（$device）" -j RETURN
						iptables -t nat -A Clash -s $ip -p tcp -m comment --comment "tcp流量禁止进入Clash内核（$device）" -j RETURN
						[ "$core_ipv6" = "开" ] && {
							ip6tables -t mangle -A Clash -s $ip -p udp -m comment --comment "udp流量禁止进入Clash内核（$device）" -j RETURN
							ip6tables -t nat -A Clash -s $ip -p tcp -m comment --comment "tcp流量禁止进入Clash内核（$device）" -j RETURN
						}
					fi
				}
				[ "$mac" ] && {
					if [ "$mac_filter_mode" = "白名单" ];then
						iptables -t mangle -A Clash -m mac --mac-source $mac -p udp -m comment --comment "udp流量进入Clash内核（$device）" -j MARK --set-mark $redir_port
						iptables -t nat -A Clash -m mac --mac-source $mac -p tcp -m comment --comment "tcp流量进入Clash内核（$device）" -j REDIRECT --to-port $redir_port
						[ "$core_ipv6" = "开" ] && {
							ip6tables -t mangle -A Clash -m mac --mac-source $mac -p udp -m comment --comment "udp流量进入Clash内核（$device）" -j MARK --set-mark $redir_port
							ip6tables -t nat -A Clash -m mac --mac-source $mac -p tcp -m comment --comment "tcp流量进入Clash内核（$device）" -j REDIRECT --to-port $redir_port
						}
					else
						iptables -t mangle -A Clash -m mac --mac-source $mac -p udp -m comment --comment "udp流量禁止进入Clash内核（$device）" -j RETURN
						iptables -t nat -A Clash -m mac --mac-source $mac -p tcp -m comment --comment "tcp流量禁止进入Clash内核（$device）" -j RETURN
						[ "$core_ipv6" = "开" ] && {
							ip6tables -t mangle -A Clash -m mac --mac-source $mac -p udp -m comment --comment "udp流量禁止进入Clash内核（$device）" -j RETURN
							ip6tables -t nat -A Clash -m mac --mac-source $mac -p tcp -m comment --comment "tcp流量禁止进入Clash内核（$device）" -j RETURN
						}
					fi
				}
			done < $CLASHDIR/maclist
		else
			[ -s $CLASHDIR/maclist ] || echo -e "#黑白名单列表（可填IP或MAC地址）\n#192.168.1.100\t我的电脑\n#aa:bb:cc:dd:ee:ff\t设备名称（可填可不填）" > $CLASHDIR/maclist
			echo -e "\n$RED常用设备名单无内容！请配置 $BLUE$CLASHDIR/maclist$RED 文件！$RESET" && sleep 2
		fi
	}
	[ "$mac_filter" != "开" -o "$mac_filter_mode" != "白名单" ] && {
		iptables -t mangle -A Clash -s $route -p udp -m comment --comment "udp流量进入Clash内核（$route网段）" -j MARK --set-mark $redir_port
		iptables -t nat -A Clash -s $route -p tcp -m comment --comment "tcp流量进入Clash内核（$route网段）" -j REDIRECT --to-port $redir_port
		[ "$core_ipv6" = "开" ] && {
			for route6 in $routev6;do
				ip6tables -t mangle -A Clash -s $route6 -p udp -m comment --comment "udp流量进入Clash内核（$route6网段）" -j MARK --set-mark $redir_port
				ip6tables -t nat -A Clash -s $route6 -p tcp -m comment --comment "tcp流量进入Clash内核（$route6网段）" -j REDIRECT --to-port $redir_port
			done
		}
	}
	[ "$wanipv4" -a "$Clash_Local_Proxy" = "开" ] && {
		iptables -t nat -N Clash_Local_Proxy
		[ "$core_ipv6" = "开" ] && ip6tables -t nat -N Clash_Local_Proxy
		if [ "$common_ports" = "开" ];then
			ports="" && amount=0 && for port in $(echo $multiports | awk -F , '{for(i=1;i<=NF;i++){print $i};}');do
				ports="$ports,$port" && let amount++
				[ $amount == 15 ] && {
					ports=$(echo $ports | sed 's/^,//')
					iptables -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					[ "$core_ipv6" = "开" ] && ip6tables -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					amount=0 && ports=""
				}
			done
			[ "$ports" ] && {
				ports=$(echo $ports | sed 's/^,//')
				iptables -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
				[ "$core_ipv6" = "开" ] && ip6tables -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
			}
		else
			iptables -t nat -A OUTPUT -p tcp -m comment --comment "tcp本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
			[ "$core_ipv6" = "开" ] && ip6tables -t nat -A OUTPUT -p tcp -m comment --comment "tcp本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
		fi
		iptables -t nat -A Clash_Local_Proxy -m owner --gid-owner $redir_port -m comment --comment "Clash 本机tcp流量防止回环" -j RETURN
		[ "$core_ipv6" = "开" ] && ip6tables -t nat -A Clash_Local_Proxy -m owner --gid-owner $redir_port -m comment --comment "Clash 本机tcp流量防止回环" -j RETURN
		[ "$dns_server_ip_filter" ] && {
			for dns_server_ip in $dns_server_ip_filter;do
				iptables -t nat -A Clash_Local_Proxy -d $dns_server_ip -p tcp -m comment --comment "tcp本机流量目的地为dns服务器地址（$dns_server_ip），直接绕过Clash内核" -j RETURN
			done
		}
		[ "$cnip_route" = "开" ] && iptables -t nat -A Clash_Local_Proxy -m set --match-set cn_ip dst -p tcp -m comment --comment "tcp本机流量目的地为国内IPv4地址，直接绕过Clash内核" -j RETURN
		[ "$core_ipv6" = "开" -a "$cnipv6_route" = "开" ] && ip6tables -t nat -A Clash_Local_Proxy -m set --match-set cn_ipv6 dst -p tcp -m comment --comment "tcp本机流量目的地为国内IPv6地址，直接绕过Clash内核" -j RETURN
		iptables -t nat -A Clash_Local_Proxy -s $wanipv4 -p tcp -m comment --comment "tcp本机流量进入Clash内核" -j REDIRECT --to-port $redir_port
		[ "$core_ipv6" = "开" ] && ip6tables -t nat -A Clash_Local_Proxy -s $wanipv6 -p tcp -m comment --comment "tcp本机流量进入Clash内核" -j REDIRECT --to-port $redir_port
	}
	return 0
}
stopfirewall(){
	while [ "$(ip6tables -t nat -S OUTPUT | grep 常用端口)" ];do
		eval ip6tables -t nat $(ip6tables -t nat -S OUTPUT | grep 常用端口 | sed 's/-A/-D/' | head -1) 2> /dev/null
	done
	ip6tables -t nat -D OUTPUT -p tcp -m comment --comment "tcp本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy 2> /dev/null
	ip6tables -t nat -F Clash_Local_Proxy 2> /dev/null
	ip6tables -t nat -X Clash_Local_Proxy 2> /dev/null
	ip6tables -D FORWARD -o utun -p udp -m comment --comment "utun出口流量允许放行" -j ACCEPT 2> /dev/null
	while [ "$(ip6tables -t nat -S PREROUTING | grep 常用端口流量)" ];do
		eval ip6tables -t nat $(ip6tables -t nat -S PREROUTING | grep 常用端口流量 | sed 's/-A/-D/' | head -1) 2> /dev/null
	done
	ip6tables -t nat -D PREROUTING -p tcp -m comment --comment "tcp流量进入Clash规则链" -j Clash 2> /dev/null
	ip6tables -t nat -F Clash 2> /dev/null
	ip6tables -t nat -X Clash 2> /dev/null
	while [ "$(ip6tables -t mangle -S PREROUTING | grep 常用端口流量)" ];do
		eval ip6tables -t mangle $(ip6tables -t mangle -S PREROUTING | grep 常用端口流量 | sed 's/-A/-D/' | head -1) 2> /dev/null
	done
	ip6tables -t mangle -D PREROUTING -p udp -m comment --comment "udp流量进入Clash规则链" -j Clash 2> /dev/null
	ip6tables -t mangle -F Clash 2> /dev/null
	ip6tables -t mangle -X Clash 2> /dev/null
	ipset -q destroy cn_ipv6
	ip -6 rule del fwmark $redir_port table 100 2> /dev/null
	while [ "$(iptables -t nat -S OUTPUT | grep 常用端口)" ];do
		eval iptables -t nat $(iptables -t nat -S OUTPUT | grep 常用端口 | sed 's/-A/-D/' | head -1) 2> /dev/null
	done
	iptables -t nat -D OUTPUT -p tcp -m comment --comment "tcp本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy 2> /dev/null
	iptables -t nat -F Clash_Local_Proxy 2> /dev/null
	iptables -t nat -X Clash_Local_Proxy 2> /dev/null
	iptables -D FORWARD -o utun -p udp -m comment --comment "utun出口流量允许放行" -j ACCEPT 2> /dev/null
	while [ "$(iptables -t nat -S PREROUTING | grep 常用端口流量)" ];do
		eval iptables -t nat $(iptables -t nat -S PREROUTING | grep 常用端口流量 | sed 's/-A/-D/' | head -1) 2> /dev/null
	done
	iptables -t nat -D PREROUTING -p tcp -m comment --comment "tcp流量进入Clash规则链" -j Clash 2> /dev/null
	iptables -t nat -F Clash 2> /dev/null
	iptables -t nat -X Clash 2> /dev/null
	while [ "$(iptables -t mangle -S PREROUTING | grep 常用端口流量)" ];do
		eval iptables -t mangle $(iptables -t mangle -S PREROUTING | grep 常用端口流量 | sed 's/-A/-D/' | head -1) 2> /dev/null
	done
	iptables -t mangle -D PREROUTING -p udp -m comment --comment "udp流量进入Clash规则链" -j Clash 2> /dev/null
	iptables -t mangle -F Clash 2> /dev/null
	iptables -t mangle -X Clash 2> /dev/null
	ipset -q destroy cn_ip
	ip rule del fwmark $redir_port table 100 2> /dev/null
	return 0
}
showfirewall(){
	echo -e "\n-------------------------------------------MANGLE-------------------------------------------" && {
		[ "$(iptables -t mangle -S PREROUTING | grep Clash)" ] && iptables -t mangle -nvL PREROUTING && echo && iptables -t mangle -nvL Clash
	}
	echo -e "\n--------------------------------------------NAT---------------------------------------------" && {
		[ "$(iptables -t nat -S PREROUTING | grep Clash)" ] && iptables -t nat -nvL PREROUTING && echo && iptables -t nat -nvL Clash
		[ "$(iptables -t nat -S OUTPUT | grep Clash)" ] && echo && iptables -t nat -nvL OUTPUT && echo && iptables -t nat -nvL Clash_Local_Proxy
	}
	echo -e "\n-------------------------------------------FILTER-------------------------------------------" && {
		[ "$(iptables -S FORWARD | grep utun)" ] && iptables -nvL FORWARD
	}
	echo -e "\n----------------------------------------IPv6  MANGLE----------------------------------------" && {
		[ "$(ip6tables -t mangle -S PREROUTING | grep Clash)" ] && ip6tables -t mangle -nvL PREROUTING && echo && ip6tables -t mangle -nvL Clash
	}
	echo -e "\n-----------------------------------------IPv6  NAT------------------------------------------" && {
		[ "$(ip6tables -t nat -S PREROUTING | grep Clash)" ] && ip6tables -t nat -nvL PREROUTING && echo && ip6tables -t nat -nvL Clash
		[ "$(ip6tables -t nat -S OUTPUT | grep Clash)" ] && echo && ip6tables -t nat -nvL OUTPUT && echo && ip6tables -t nat -nvL Clash_Local_Proxy
	}
	echo -e "\n----------------------------------------IPv6  FILTER----------------------------------------" && {
		[ "$(ip6tables -S FORWARD | grep utun)" ] && ip6tables -nvL FORWARD
	}
}
#修复小米AX9000开启QOS时若Clash-mihomo正在运行而导致某些特定udp端口流量（如80 8080等）无法通过问题
[ "$(uci get /usr/share/xiaoqiang/xiaoqiang_version.version.HARDWARE 2> /dev/null)" = "RA70" ] && \
sed -i "s@\[ -d /sys/module/shortcut_fe_cm ] |@\[ -d /sys/module/shortcut_fe_cm -o -n \"\$(pidof mihomo)\" ] |@" /etc/init.d/shortcut-fe
main(){
	saveconfig && num="$1" && ids="" && [ ! "$num" ] && {
		echo -e "========================================================="
		[ -s $CLASHDIR/starttime -a "$(pidof mihomo)" ] && echo -e "${BLUE}Clash-mihomo $YELLOW运行中 运存占用：$RED$(awk BEGIN'{printf "%0.2f MB",'$(cat /proc/$(pidof mihomo)/status 2> /dev/null | grep -w VmRSS | awk '{print $2}')'/1024}') $YELLOW运行时长：$RED$(date -u -d @$(($(date +%s)-$(cat $CLASHDIR/starttime))) +%H时%M分%S秒)$RESET" || echo -e "${BLUE}Clash-mihomo $RED没有运行！$RESET"
		echo "========================================================="
		echo "请输入你的选项："
		echo "---------------------------------------------------------"
		echo -e "1. $GREEN重新启动 ${BLUE}Clash-mihomo$RESET"
		echo -e "2. $RED停止运行 ${BLUE}Clash-mihomo$RESET"
		[ "$common_ports" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "3. $GREEN开启$RESET/$RED关闭 $SKYBLUE仅代理常用端口\t\t$YELLOW当前状态：$states$RESET"
		[ "$cnip_route" = "开" -o "$cnipv6_route" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "4. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}CNIP绕过内核\t\t$YELLOW当前状态：$states$RESET"
		[ "$Clash_Local_Proxy" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "5. $GREEN开启$RESET/$RED关闭 $SKYBLUE本机流量代理\t\t$YELLOW当前状态：$states$RESET"
		[ "$mac_filter" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "6. $GREEN开启$RESET/$RED关闭 $SKYBLUE常用设备过滤\t\t$YELLOW当前状态：$states$RESET"
		[ "$mac_filter_mode" = "黑名单" ] && states="$PINK黑名单" || states="$GREEN白名单"
		echo -e "7. $YELLOW切换 $SKYBLUE常用设备过滤模式\t\t$YELLOW当前状态：$states$RESET"
		echo -e "8. $YELLOW查看 $SKYBLUE防火墙相关规则$RESET"
		echo -e "9. $YELLOW更新 $SKYBLUE所有相关文件$RESET"
		echo "---------------------------------------------------------"
		echo -ne "\n"
		read -p "请输入对应选项的数字 > " num
	}
	case "$num" in
		1)start;;
		2)stop;;
		3)
			[ "$common_ports" = "开" ] && common_ports=关 || common_ports=开
			[ "$(pidof mihomo)" ] && startfirewall;main;;
		4)
			echo "=========================================================" && cniproutenum=""
			echo "请输入你的选项："
			echo "---------------------------------------------------------"
			[ "$cnip_route" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
			echo -e "1. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}CNIPv4绕过内核\t\t$YELLOW当前状态：$states$RESET"
			[ "$cnipv6_route" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
			echo -e "2. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}CNIPv6绕过内核\t\t$YELLOW当前状态：$states$RESET"
			echo "---------------------------------------------------------"
			echo -e "0. 返回上一页"
			echo -ne "\n"
			read -p "请输入对应选项的数字 > " cniproutenum
			case "$cniproutenum" in
				1)
					[ "$cnip_route" = "开" ] && cnip_route=关 || cnip_route=开
					[ "$(pidof mihomo)" ] && startfirewall;main $num;;
				2)
					[ "$cnipv6_route" = "开" ] && cnipv6_route=关 || cnipv6_route=开
					[ "$(pidof mihomo)" ] && startfirewall;main $num;;
				0)main;;
			esac;;
		5)
			[ "$Clash_Local_Proxy" = "开" ] && Clash_Local_Proxy=关 || Clash_Local_Proxy=开
			[ "$(pidof mihomo)" ] && startfirewall;main;;
		6)
			[ "$mac_filter" = "开" ] && mac_filter=关 || mac_filter=开
			[ "$(pidof mihomo)" ] && startfirewall;main;;
		7)
			[ "$mac_filter_mode" = "黑名单" ] && mac_filter_mode=白名单 || mac_filter_mode=黑名单
			[ "$(pidof mihomo)" ] && startfirewall;main;;
		8)showfirewall;;
		9)update;;
	esac
}
case "$1" in
	1|start)start;;
	2|stop)stop;;
	8|showfirewall)showfirewall;;
	9|update)update;;
	*)main;;
esac
