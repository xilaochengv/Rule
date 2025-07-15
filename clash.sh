CLASHDIR=$(dirname $0) && [ -s $CLASHDIR/config.ini ] && . $CLASHDIR/config.ini
RED='\e[0;31m';GREEN='\e[1;32m';YELLOW='\e[1;33m';BLUE='\e[1;34m';PINK='\e[1;35m';SKYBLUE='\e[1;36m';RESET='\e[0m'
[ ! "$(grep CLASHDIR /etc/profile)" ] && echo -e "$YELLOW脚本提示：现在退出并重进SSH即可直接使用clash命令呼叫菜单$RESET" && sleep 1
sed -i '/clash=/d' /etc/profile && echo -e "\nexport CLASHDIR=$(dirname $0);alias clash=\"$0\"" >> /etc/profile && sed -i '/./,/^$/!d' /etc/profile
[ ! "$(uci -q get firewall.firewalluser.path)" ] && echo -e "config inculde 'firewalluser'\n\toption path '/etc/firewall.user'\n\toption reload '1'" >> /etc/config/firewall && sed -i '/./,/^$/!d' /etc/config/firewall
sed -i '/clash/d' /etc/firewall.user 2> /dev/null;[ ! "$(grep "$0 start$" /etc/firewall.user 2> /dev/null)" ] && echo -e "[ \"\$(pidof mihomo)\" ] && $0 startfirewall" >> /etc/firewall.user
route=$(ip route | grep br-lan | awk {'print $1'})
routes="10.0.0.0/8\n100.64.0.0/10\n127.0.0.0/8\n169.254.0.0/16\n172.16.0.0/12\n192.168.0.0/16\n224.0.0.0/4\n240.0.0.0/4\n$route";routes=$(echo -e $routes | awk '!a[$0]++')
[ "$(uci -q get ipv6.settings.enabled)" = 0 ] && for routev6 in $(ip -6 route | awk '{print $1}');do ip -6 route del $routev6;done
routev6=$(ip -6 route | grep br-lan | awk '{print $1}')
routesv6="::1 $routev6"
localip=$(ip route | grep br-lan | awk {'print $9'})
wanipv4=$(ip -o addr | grep pppoe-wan | grep 'inet ' | awk '{print $4}')
wanipv6=$(ip -o addr | grep pppoe-wan | grep inet6.*global | sed -e 's/.*inet6 //' -e 's#/.*##')
[ ! "$tls13" ] && tls13=关
[ ! "$udp_support" ] && udp_support=关
[ ! "$skip_cert_verify" ] && skip_cert_verify=关
[ ! "$subconverter" ] && subconverter=开
[ ! "$sub_url" ] && sub_url=https://url.v1.mk
[ ! "$geoip_url" ] && geoip_url=https://github.com/xilaochengv/Rule/releases/download/Latest/geoip.dat
[ ! "$geosite_url" ] && geosite_url=https://github.com/xilaochengv/Rule/releases/download/Latest/geosite.dat
[ ! "$redirect_mode" ] && redirect_mode=mixed
[ ! "$dns_mode" ] && dns_mode=redir-host
[ ! "$redir_port" ] && redir_port=25274
[ ! "$mixed_port" ] && mixed_port=25275
[ ! "$tproxy_port" ] && tproxy_port=25276
[ ! "$dashboard_port" ] && dashboard_port=6789
[ ! "$core_ipv6" ] && core_ipv6=开
[ ! "$dns_ipv6" ] && dns_ipv6=开
[ ! "$dns_hijack" ] && dns_hijack=关
[ ! "$dnsipv6_hijack" -o "$dns_ipv6" != "开" -o "$(cat $CLASHDIR/config.yaml 2> /dev/null | grep '^ .*ipv6:'| awk '{print $2}')" != "true" ] && dnsipv6_hijack=关
[ ! "$dns_port" ] && dns_port=1053
[ ! "$dns_default" ] && dns_default='223.6.6.6' || dns_default=$(echo $dns_default | sed 's/,/, /g')
[ ! "$dns_oversea" ] && dns_oversea='https://basic.rethinkdns.com, https://dns.rabbitdns.org/dns-query' || dns_oversea=$(echo $dns_oversea | sed 's/,/, /g')
[ ! "$mac_filter" ] && mac_filter=关
[ ! "$mac_filter_mode" ] && mac_filter_mode=黑名单
[ ! "$cnip_skip" ] && cnip_skip=关
[ ! "$cnipv6_skip" ] && cnipv6_skip=关
[ ! "$common_ports" ] && common_ports=关
[ ! "$multiports" ] && multiports=53,80,123,143,194,443,465,587,853,993,995,5222,8080,8443
[ ! "$Docker_Proxy" -o ! "$(ip route | grep docker | awk '{print $1}' | head -1)" ] && Docker_Proxy=关
[ ! "$Clash_Local_Proxy" ] && Clash_Local_Proxy=关
[ -s $CLASHDIR/custom_rules.ini ] || echo -e "#说明文档：https://wiki.metacubex.one/config/rules\n#填写格式：\n#DOMAIN,baidu.com,DRIECT（不需要填前面的-符号）" > $CLASHDIR/custom_rules.ini
[ ! "$(grep ^http $CLASHDIR/mirror_server.ini 2> /dev/null)" ] && echo -e "https://ghproxy.net\nhttps://cdn.gh-proxy.com\nhttps://ghfast.top" > $CLASHDIR/mirror_server.ini
[ ! "$(grep http $CLASHDIR/convert_server.ini 2> /dev/null)" ] && echo -e "品云提供 https://sub.id9.cc\n品云备用 https://v.id9.cc\n肥羊增强 https://url.v1.mk\n肥羊备用 https://sub.d1.mk\nnameless13提供 https://www.nameless13.com\nsubconverter作者提供 https://sub.xeton.dev\nsub-web作者提供 https://api.wcc.best\nsub作者 & lhie1提供 https://api.dler.io" > $CLASHDIR/convert_server.ini
[ ! "$(grep http $CLASHDIR/config_url.ini 2> /dev/null)" ] && echo -e "作者自用GEO精简规则 https://raw.githubusercontent.com/xilaochengv/Rule/main/rule.ini\n默认版规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini\n精简版规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini\n更多去广告规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_AdblockPlus.ini\n多国分组规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_MultiCountry.ini\n无自动测速规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoAuto.ini\n无广告拦截规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoReject.ini\n全分组规则 重度用户使用 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini" > $CLASHDIR/config_url.ini
Filesystem=$(dirname $0);while [ ! "$(df $Filesystem)" ];do Filesystem=$(echo ${Filesystem%/*});done;Filesystem=$(df $Filesystem | tail -1 | awk '{print $6}');Available=$(df $Filesystem | tail -1 | awk '{print $4}')
[ ! -f $CLASHDIR/config.ini -a $Available -lt 1024 ] && echo -e "$RED当前脚本存放位置 $BLUE$0 $RED的所在分区 $BLUE$Filesystem $RED空间过小！请更换本脚本存放位置！$RESET" && exit
start(){
	stop start && update missingfiles
	[ "$authusername" -a "$authpassword" ] && authentication="authentication: [\"$authusername:$authpassword\"]"
	[ "$core_ipv6" = "开" ] && ipv6_core=true || ipv6_core=false
	[ "$dns_ipv6" = "开" ] && ipv6_dns=true || ipv6_dns=false
	[ "$(grep -i geosite $CLASHDIR/config_original.yaml)" -o "$dns_mode" = "mixed" ] && {
		nameserverpolicy="'geosite: cn,apple': [$dns_default]"
		fakeipfilter_geosite="    - geosite:cn,apple\n"
	}
	case "$dns_mode" in
		fake-ip)
			fakeipfilter="    - '*.lan'\n    - '*.localdomain'\n    - '*.example'\n    - '*.invalid'\n    - '*.localhost'\n    - '*.test'\n    - '*.local'\n    - '*.home.arpa'\n    - '*.direct'";;
		mixed)
			fakeipfilter="$fakeipfilter_geosite$(grep -v '^#' $CLASHDIR/fake_ip_filter.list | sed "s/.*/    - '&'/")";;
		*)
			fakeipfilter="    - '+.*'";;
	esac
	[ "$redirect_mode" = "mixed" ] && tun="{ enable: true, stack: mixed, device: utun, auto-route: false, udp-timeout: 60 }" || {
		modprobe xt_TPROXY 2> /dev/null && [ "$?" = 0 ] && tun="{ enable: false }" || {
			redirect_mode=mixed
			echo -e "\n${BLUE}TPROXY $RED内核模块不存在，已自动切换成 ${PINK}Mixed$RED（${YELLOW}REDIRECT + utun$RED）模式！$RESET"
			tun="{ enable: true, stack: mixed, device: utun, auto-route: false, udp-timeout: 60 }" && saveconfig
		}
	}
	cat > $CLASHDIR/config.yaml << EOF
redir-port: $redir_port
mixed-port: $mixed_port
tproxy-port: $tproxy_port
allow-lan: true
$authentication
log-level: debug
ipv6: $ipv6_core
keep-alive-interval: 30
find-process-mode: "off"
external-controller: :$dashboard_port
external-ui: ui
profile:
  store-selected: true
unified-delay: true
geodata-mode: true
geox-url:
  geoip: "$(echo $mirrorserver | sed 's/[^/]$/&\//')$geoip_url"
  geosite: "$(echo $mirrorserver | sed 's/[^/]$/&\//')$geosite_url"
dns:
  enable: true
  listen: :$dns_port
  ipv6: $ipv6_dns
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
$(echo -e "$fakeipfilter")
  fake-ip-filter-mode: blacklist
  default-nameserver:
    - 223.6.6.6
  nameserver-policy:
    $nameserverpolicy
  nameserver: [$dns_oversea]
  proxy-server-nameserver: [$dns_default]
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  sniff:
    http: { ports: [1-65535] }
    tls: { ports: [1-65535] }
    quic: { ports: [1-65535] }
  skip-domain:
    - Mijia Cloud
    - dlg.io.mi.com
tun: $tun
$(sed -n '/^proxies/,/^rules/p' $CLASHDIR/config_original.yaml)
EOF
	sed -n '/^rules/,/*/p' $CLASHDIR/config_original.yaml | tail +2 > $CLASHDIR/rules.yaml && sed -i "s/\'//g;s/GEOIP.*/&,no-resolve/" $CLASHDIR/rules.yaml
	spaces=$(sed -n 1p $CLASHDIR/rules.yaml | grep -oE '^ *- *')
	while read LINE;do
		[ "$(echo $LINE | grep -v '^#')" ] && {
			groupname=$(echo $LINE | awk -F , '{print $3}') && [ "$(grep -E "\- $groupname$|\- name: $groupname$|'$groupname'|\[$groupname,|, $groupname,|, $groupname]" $CLASHDIR/config.yaml)" ] && \
			echo $LINE | sed "s/.*/$spaces&\t#自定义规则/" >> $CLASHDIR/config.yaml || \
			echo -e "$YELLOW\n自定义规则 $PINK$LINE$YELLOW 中的节点 $PINK$groupname$YELLOW 不存在，已自动忽略添加本条自定义规则！$RESET"
		}
	done < $CLASHDIR/custom_rules.ini
	cat $CLASHDIR/rules.yaml >> $CLASHDIR/config.yaml && rm -f $CLASHDIR/rules.yaml
	error="$($CLASHDIR/mihomo -d $CLASHDIR -t $CLASHDIR/config.yaml | grep error | awk -F = '{print $3"="$NF}')"
	[ "$error" ] && echo -e "\n${BLUE}Clash-mihomo $RED启动失败！\n$RESET\n$error\n" && exit
	sed -i '/Clash/d' /etc/passwd && echo "Clash:x:0:$redir_port:::" >> /etc/passwd
	modprobe tun 2> /dev/null
	start-stop-daemon -Sbc Clash:$redir_port -x $CLASHDIR/mihomo -- -d $CLASHDIR &
	[ "$redirect_mode" = "tproxy" ] || while [ ! "$(ifconfig | grep utun)" ];do usleep 100000;done
	startfirewall && date +%s > $CLASHDIR/starttime
	curl -so /dev/null "http://127.0.0.1:$dashboard_port/group/节点选择/delay?url=https://www.google.com/generate_204&timeout=5000" &
	echo -e "hosto=\$(ip route | grep br-lan | awk {'print \$9'})\nipv4o=\$(ip -o addr | grep pppoe-wan | grep 'inet ' | awk '{print \$4}')\nipv6o=\$(ip -o addr | grep pppoe-wan | grep inet6.*global | sed -e 's/.*inet6 //' -e 's#/.*##')\nwhile [ \"\$(pidof mihomo)\" ];do\n\tsleep 10\n\thostn=\$(ip route | grep br-lan | awk {'print \$9'})\n\tipv4n=\$(ip -o addr | grep pppoe-wan | grep 'inet ' | awk '{print \$4}')\n\tipv6n=\$(ip -o addr | grep pppoe-wan | grep inet6.*global | sed -e 's/.*inet6 //' -e 's#/.*##')\n\t[ \"\$hostn\" -a \"\$hosto\" != \"\$hostn\" -o \"\$ipv4n\" -a \"\$ipv4o\" != \"\$ipv4n\" -o \"\$ipv6n\" -a \"\$ipv6o\" != \"\$ipv6n\" ] && { hosto=\$hostn && ipv4o=\$ipv4n && ipv6o=\$ipv6n && $0 startfirewall; }\n\t[ \$(awk 'NR==3{print \$2}' /proc/meminfo) -lt 102400 ] && curl -so /dev/null \"http://127.0.0.1:$dashboard_port/debug/gc\" -X PUT\n\t[ ! \"\$(iptables -w -t mangle -S Clash 2> /dev/null)\" ] && $0 startfirewall\ndone" > /tmp/autooc.sh && chmod 755 /tmp/autooc.sh && /tmp/autooc.sh &
	echo -e "\n${BLUE}Clash-mihomo $GREEN启动成功！$YELLOW面板管理页面：$SKYBLUE$localip:$dashboard_port/ui$RESET\n" && rm -f $CLASHDIR/config_original.yaml.backup
	rm -f $CLASHDIR/config_original_temp_*.yaml $CLASHDIR/proxy-groups_temp_*.yaml $CLASHDIR/proxies.yaml $CLASHDIR/proxy-groups.yaml $CLASHDIR/rules.yaml
	#修复小米AX9000开启QOS功能情况下某些特定udp端口（如80 8080等）流量无法通过问题
	[ "$(uci get /usr/share/xiaoqiang/xiaoqiang_version.version.HARDWARE 2> /dev/null)" = "RA70" ] && [ -d /sys/module/shortcut_fe_cm ] && rmmod shortcut-fe-cm &> /dev/null
	return 0
}
stop(){
	killall mihomo 2> /dev/null
	stopfirewall && rm -f $CLASHDIR/starttime
	while [ "$(ps | grep -v grep | grep autooc)" ];do killpid $(ps | grep -v grep | grep autooc | head -1 | awk '{print $1}');done
	[ ! "$1" ] && echo -e "\n${BLUE}Clash-mihomo $RED已停止服务！$RESET"
	#AX9000若QOS功能开启则恢复加载数据小包加速管理中心模块
	[ "$(uci get /usr/share/xiaoqiang/xiaoqiang_version.version.HARDWARE 2> /dev/null)" = "RA70" ] && [ -d /sys/module/shortcut_fe ] && insmod shortcut-fe-cm &> /dev/null
	return 0
}
saveconfig(){
	echo "sublink='$sublink' #订阅链接地址，如有多个订阅链接地址请用竖线‘|’隔开" > $CLASHDIR/config.ini
	echo "subconverter=$subconverter #是否使用订阅配置转换服务" >> $CLASHDIR/config.ini
	echo "subconverter_path=$subconverter_path #本地后端转换程序路径" >> $CLASHDIR/config.ini
	echo "sub_url='$sub_url' #订阅配置转换服务器地址" >> $CLASHDIR/config.ini
	echo "config_url='$config_url' #订阅配置转换规则文件地址（仅在订阅配置转换服务为开时可用）" >> $CLASHDIR/config.ini
	echo "exclude_name='$exclude_name' #过滤包含关键字的节点（仅在订阅配置转换服务为开时可用，如有多个关键字请用竖线‘|’隔开）" >> $CLASHDIR/config.ini
	echo "exclude_type='$exclude_type' #过滤包含关键字的节点类型（仅在订阅配置转换服务为开时可用，如有多个关键字请用竖线‘|’隔开）" >> $CLASHDIR/config.ini
	echo "udp_support=$udp_support #是否开启udp代理（仅在订阅配置转换服务为开时可用，需要机场节点支持）" >> $CLASHDIR/config.ini
	echo "tls13=$tls13 #是否开启节点的tls1.3功能" >> $CLASHDIR/config.ini
	echo "skip_cert_verify=$skip_cert_verify #是否开启跳过TLS节点的证书验证功能" >> $CLASHDIR/config.ini
	echo "mirrorserver='$mirrorserver' #Github加速镜像服务器地址" >> $CLASHDIR/config.ini
	echo "geoip_url='$geoip_url' #GEO-IP数据库文件下载地址" >> $CLASHDIR/config.ini
	echo "geosite_url='$geosite_url' #GEO-SITE数据库文件下载地址" >> $CLASHDIR/config.ini
	echo -e "\n#以下配置修改后，需要运行脚本并选择1重启Clash-mihomo后才能生效" >> $CLASHDIR/config.ini
	echo "redirect_mode=$redirect_mode #流量代理模式（可选mixed或tproxy）" >> $CLASHDIR/config.ini
	echo "dns_mode=$dns_mode #DNS解析模式（可选redir-host或mixed或fake-ip）" >> $CLASHDIR/config.ini
	echo "redir_port=$redir_port #透明代理端口" >> $CLASHDIR/config.ini
	echo "mixed_port=$mixed_port #http(s)和socks混合代理端口" >> $CLASHDIR/config.ini
	echo "tproxy_port=$tproxy_port #TPROXY透明代理端口" >> $CLASHDIR/config.ini
	echo "authusername='$authusername' #http(s),socks入口的验证用户名" >> $CLASHDIR/config.ini
	echo "authpassword='$authpassword' #http(s),socks入口的验证密码" >> $CLASHDIR/config.ini
	echo "dashboard_port=$dashboard_port #网页UI面板监听端口" >> $CLASHDIR/config.ini
	echo "core_ipv6=$core_ipv6 #是否开启IPv6流量代理功能" >> $CLASHDIR/config.ini
	echo "dns_ipv6=$dns_ipv6 #是否开启IPv6 DNS解析功能" >> $CLASHDIR/config.ini
	echo "dns_port=$dns_port #DNS服务监听端口" >> $CLASHDIR/config.ini
	echo "dns_default='$dns_default' #默认DNS解析服务器，如有多个请用逗号‘,’隔开" | sed 's/, /,/g' >> $CLASHDIR/config.ini
	echo "dns_oversea='$dns_oversea' #海外DNS解析服务器，如有多个请用逗号‘,’隔开" | sed 's/, /,/g' >> $CLASHDIR/config.ini
	echo -e "\n#以下配置修改后，需要运行脚本并选择4-9随意一项后才可生效" >> $CLASHDIR/config.ini
	echo "dns_hijack=$dns_hijack #是否开启DNS IPv4解析服务流量劫持功能（开启后所有IPv4通过53端口的流量将直接转发到mihomo内核上进行DNS解析）" >> $CLASHDIR/config.ini
	echo "dnsipv6_hijack=$dnsipv6_hijack #是否开启DNS IPv6解析服务流量劫持功能（开启后所有IPv6通过53端口的流量将直接转发到mihomo内核上进行DNS解析）" >> $CLASHDIR/config.ini
	echo "mac_filter=$mac_filter #是否开启常用设备过滤功能" >> $CLASHDIR/config.ini
	echo "mac_filter_mode=$mac_filter_mode #常用设备过滤功能工作模式（黑名单或白名单）" >> $CLASHDIR/config.ini
	echo "cnip_skip=$cnip_skip #是否开启国内IPv4流量绕过核心功能（减轻运行内存负担）" >> $CLASHDIR/config.ini
	echo "cnipv6_skip=$cnipv6_skip #是否开启国内IPv6流量绕过核心功能（减轻运行内存负担）" >> $CLASHDIR/config.ini
	echo "common_ports=$common_ports #是否开启仅常用端口代理功能" >> $CLASHDIR/config.ini
	multiports=$(echo $multiports | sed 's/[^0-9\-]/,/g')
	echo "multiports=$multiports #常用端口（如有多个请用逗号‘,’隔开，连续的端口可以用‘-’符号连接，如：80,123,400-432,8080）" >> $CLASHDIR/config.ini
	echo "Docker_Proxy=$Docker_Proxy #是否开启Docker流量代理功能" >> $CLASHDIR/config.ini
	echo "Clash_Local_Proxy=$Clash_Local_Proxy #是否开启本机流量代理功能" >> $CLASHDIR/config.ini
	[ ! "$(echo $sublink | awk '{print $1}' | grep -E '^http://.*\.[^$]|^https://.*\.[^$]')" ] && {
		[ "$1" ] || echo -e "\n$RED请先填写好订阅链接地址！$RESET\n"
		read -p "请输入订阅链接地址（如有多个请用竖线‘|’隔开）：" sublink
		if [ "$(echo $sublink | awk '{print $1}' | grep -E '^http://.*\.[^$]|^https://.*\.[^$]')" ];then
			saveconfig && echo -e "\n$YELLOW填写成功！当前订阅链接地址：$SKYBLUE$sublink$RESET" && sleep 1
		elif [ "$sublink" ];then
			echo -e "\n$YELLOW请输入正确格式以http开头的订阅链接地址！$RESET\n" && sleep 1 && saveconfig retype
		else
			echo -e "\n$RED放弃输入，已自动退出脚本！$RESET\n" && exit
		fi
	}
	return 0
}
urlencode() {
	i=0
	length="${#1}"
	while [ true ];do
		[ $length -gt $i ] && {
			c="${1:$i:1}"
			case $c in
				[a-zA-Z0-9.~_-]) printf "$c";;
				*) printf '%%%02X' "'$c";;
			esac
		} || break
		let i++
	done;echo
}
download(){
	rm -f $1 && http_code=0 && dlurl=$3 && [ "$(echo $3 | grep -vE '/http|=http' | grep -E 'github.com/|githubusercontent.com/')" -a "$mirrorserver" ] && dlurl="$(echo $3 | sed "s#.*#$(echo $mirrorserver | sed 's/[^/]$/&\//')&#")"
	[ "$4" ] && {
		echo -e "\n$YELLOW获取$2文件大小······$RESET \c" && failedcount=1 && Available=$(df $Filesystem | tail -1 | awk '{print $4}')
		size=$(curl -m 10 -skIL "$dlurl" | grep content-length | tail -1 | awk '{print $2}')
		while [ ! "$size" -a $failedcount -lt 3 ];do
			echo -e "$RED获取失败！即将尝试重新获取！已尝试获取次数：$failedcount$RESET" && sleep 1 && let failedcount++
			echo -e "\n$YELLOW获取$2文件大小······$RESET \c" && size=$(curl -m 10 -skIL ""$dlurl"" | grep content-length | tail -1 | awk '{print $2}')
		done
		[ ! "$size" ] && {
			if [ "$(echo "$dlurl" | grep -vE '/http|=http' | grep -E 'github.com/|githubusercontent.com/')" ];then
				for mirrorserver in $(cat $CLASHDIR/mirror_server.ini);do
					echo -e "$RED获取失败！即将尝试切换加速镜像重新获取！$RESET" && sleep 1 && failedcount=1
					dlurl="$(echo "$dlurl" | sed "s#.*#$(echo $mirrorserver | sed 's/[^/]$/&\//')&#")"
					echo -e "\n$YELLOW获取$2文件大小，当前尝试加速镜像：$SKYBLUE$mirrorserver $YELLOW······$RESET \c"
					size=$(curl -m 10 -skIL "$dlurl" | grep content-length | tail -1 | awk '{print $2}')
					while [ ! "$size" -a $failedcount -lt 3 ];do
						echo -e "$RED获取失败！即将尝试重新获取！已尝试获取次数：$failedcount$RESET" && sleep 1 && let failedcount++
						echo -e "\n$YELLOW获取$2文件大小，当前尝试加速镜像：$SKYBLUE$mirrorserver $YELLOW······$RESET \c" && size=$(curl -m 10 -skIL ""$dlurl"" | grep content-length | tail -1 | awk '{print $2}')
					done
					[ "$size" ] && mirrorserver=$mirrorserver && size=$(($((size/1024))+$((4-$((size/1024%4))%4)))) && echo -e "$GREEN获取成功！文件大小：$BLUE$size $GREEN，当前可用：$BLUE$Available$RESET" && saveconfig && break
				done
				[ "$size" ] && [ $Available -lt $size ] && echo -e "\n$RED当前脚本存放位置 $BLUE$0 $RED的所在分区 $BLUE$Filesystem $RED空间过小！请更换本脚本存放位置！$RESET\n" && return 1 || size=""
			else
				return 1
			fi
		}
		[ "$size" ] && size=$(($((size/1024))+$((4-$((size/1024%4))%4)))) && echo -e "$GREEN获取成功！文件大小：$BLUE$size $GREEN，当前可用：$BLUE$Available$RESET" && [ $Available -lt $size ] && echo -e "\n$RED当前脚本存放位置 $BLUE$0 $RED的所在分区 $BLUE$Filesystem $RED空间过小！请更换本脚本存放位置！$RESET\n" && return 1
	}
	echo -e "\n$YELLOW下载$2 $SKYBLUE$dlurl $YELLOW······$RESET \c" && failedcount=1
	http_code=$(curl -m 10 -sLko $1 "$dlurl" -w "%{http_code}")
	while [ $http_code != 200 -a $failedcount -lt 3 ];do
		rm -f $1 && echo -e "$RED下载失败！即将尝试重新下载！已尝试下载次数：$failedcount$RESET" && sleep 1 && let failedcount++
		echo -e "\n$YELLOW下载$2 $SKYBLUE$dlurl $YELLOW······$RESET \c" && http_code=$(curl -m 10 -sLko $1 "$dlurl" -w "%{http_code}")
	done
	[ $http_code != 200 ] && {
		if [ "$(echo $3 | grep -vE '/http|=http' | grep -E 'github.com/|githubusercontent.com/')" ];then
			for mirrorserver in $(cat $CLASHDIR/mirror_server.ini);do
				rm -f $1 && echo -e "$RED下载失败！即将尝试切换加速镜像重新下载！$RESET" && sleep 1 && failedcount=1
				dlurl="$(echo $3 | sed "s#.*#$(echo $mirrorserver | sed 's/[^/]$/&\//')&#")"
				echo -e "\n$YELLOW下载$2 $SKYBLUE$dlurl $YELLOW······$RESET \c"
				http_code=$(curl -m 10 -sLko $1 "$dlurl" -w "%{http_code}")
				while [ $http_code != 200 -a $failedcount -lt 3 ];do
					rm -f $1 && echo -e "$RED下载失败！即将尝试重新下载！已尝试下载次数：$failedcount$RESET" && sleep 1 && let failedcount++
					echo -e "\n$YELLOW下载$2 $SKYBLUE$dlurl $YELLOW······$RESET \c" && http_code=$(curl -m 10 -sLko $1 "$dlurl" -w "%{http_code}")
				done
				[ $http_code = 200 ] && mirrorserver=$mirrorserver && echo -e "$GREEN下载成功！$RESET" && saveconfig && return 0
			done
			rm -f $1 && return 1
		else
			rm -f $1 && return 1
		fi
	}
	echo -e "$GREEN下载成功！$RESET"
}
update(){
	while [ "$(cat /proc/xiaoqiang/boot_status)" != 3 ];do sleep 1;done
	[ ! "$1" -o "$1" = "crontab" ] && stop && rm -rf $CLASHDIR/ui $CLASHDIR/cn_ip.txt $CLASHDIR/cn_ipv6.txt $CLASHDIR/config.yaml $CLASHDIR/fake_ip_filter.list $CLASHDIR/GeoIP.dat $CLASHDIR/GeoSite.dat && mv -f $CLASHDIR/config_original.yaml $CLASHDIR/config_original.yaml.backup 2> /dev/null
	[ ! "$1" ] && rm -f $CLASHDIR/mihomo
	[ ! -d $CLASHDIR/ui ] && {
		download "/tmp/dashboard" "Meta基础面板" "https://raw.githubusercontent.com/juewuy/ShellCrash/dev/bin/dashboard/meta_db.tar.gz"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
		mkdir -m 755 $CLASHDIR/ui && tar -zxf /tmp/dashboard -C $CLASHDIR/ui && rm -f /tmp/dashboard
		sed -i "s/9090/$dashboard_port/g;s/127.0.0.1/$localip/g" $CLASHDIR/ui/assets/index.628acf3b.js
	}
	[ ! -f $CLASHDIR/mihomo ] && {
		while [ ! "$latestversion" ];do latestversion=$(curl --connect-timeout 3 -sk "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" | grep tag_name | cut -f4 -d '"');done
		download "/tmp/mihomo.gz" "Clash主程序文件" "https://github.com/MetaCubeX/mihomo/releases/download/$latestversion/mihomo-linux-arm64-$latestversion.gz"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
		rm -f $CLASHDIR/mihomo /tmp/mihomo && gzip -d /tmp/mihomo.gz && chmod 755 /tmp/mihomo && mv -f /tmp/mihomo $CLASHDIR/mihomo 2> /dev/null || ln -sf /tmp/mihomo $CLASHDIR/mihomo
	}
	[ ! -f $CLASHDIR/config_original.yaml ] && {
		if [ "$subconverter" = "开" ];then
			[ "$subconverter_path" ] && $subconverter_path &> /dev/null & sleep 1
			subs=1 && for url in $(echo $sublink | sed 's/|/ /g');do
				[ "$udp_support" = "开" ] && sub_udp="&udp=true"
				[ "$tls13" = "开" ] && sub_tls13="&tls13=true"
				[ "$skip_cert_verify" = "开" ] && "&sub_scv=true"
				sublink_urlencode="&url=$(urlencode "$url")";[ "$config_url" ] && config_url_urlencode="&config=$(urlencode "$config_url")"
				download "$CLASHDIR/config_original_temp_$subs.yaml" "配置文件" "$sub_url/sub?target=clash$sublink_urlencode$config_url_urlencode$sub_scv$sub_udp$sub_tls13"
				while [ "$(ps | grep -v grep | grep "$subconverter_path" 2> /dev/null | head -1 | awk '{print $1}')" ];do killpid $(ps | grep -v grep | grep "$subconverter_path" | head -1 | awk '{print $1}');done
				[ $failedcount -eq 3 -a ! -f $CLASHDIR/config_original_temp_$subs.yaml ] && {
					if [ -f $CLASHDIR/config_original.yaml.backup ];then
						echo -e "$YELLOW下载失败！即将尝试使用备份配置文件运行！$RESET"
						mv -f $CLASHDIR/config_original.yaml.backup $CLASHDIR/config_original.yaml && [ ! "$1" -o "$1" = "crontab" ] && update restore || update missingfiles;return 1
					else
						echo -e "$RED下载失败！已自动退出脚本$RESET" && rm -f $CLASHDIR/config_original_temp_*.yaml && exit
					fi
				}
				sed -n '/^rules/,/*/p' $CLASHDIR/config_original_temp_$subs.yaml > $CLASHDIR/rules.yaml
				sed -n '/^proxy-groups/,/^rules/p' $CLASHDIR/config_original_temp_$subs.yaml | tail +2 > $CLASHDIR/proxy-groups_temp_$subs.yaml
				sed -n '/^proxies/,/^proxy-groups/p' $CLASHDIR/config_original_temp_$subs.yaml | tail +2 >> $CLASHDIR/proxies.yaml && sed -i '/proxy-groups/d' $CLASHDIR/proxies.yaml && let subs++
			done
			for group in $(grep '\- name:' $CLASHDIR/proxy-groups_temp_1.yaml | awk '{for(i=3;i<=NF;i++){printf"%s ",$i};print out}' | sed 's/.$//;s/^/#/;s/$/#/;s/ /*/g');do
				group="$(echo $group | sed 's/#//g;s/*/ /g')"
				sed -n "/: $group/,/^      -/p" $CLASHDIR/proxy-groups_temp_1.yaml | head -n -1 >> $CLASHDIR/proxy-groups.yaml
				sed -n "/: $group/,/^  -/p" $CLASHDIR/proxy-groups_temp_1.yaml | grep '    -' >> $CLASHDIR/proxy-groups.yaml
				subcount=2 && while [ $subcount -lt $subs ];do
					for proxie in $(sed -n "/: $group/,/^  -/p" $CLASHDIR/proxy-groups_temp_$subcount.yaml | grep '    -' | awk '{for(i=2;i<=NF;i++){printf"%s ",$i};print out}' | sed 's/.$//;s/^/#/;s/$/#/;s/ /*/g');do
						proxie=$(echo $proxie | sed 's/#//g;s/*/ /g')
						[ ! "$(sed -n "/: $group/,/*/p" $CLASHDIR/proxy-groups.yaml | grep "$proxie")" ] && echo "      - $proxie" >> $CLASHDIR/proxy-groups.yaml
					done
					let subcount++
				done
			done && echo testing >> $CLASHDIR/proxy-groups.yaml && {
				[ "$exclude_name" ] && exclude_name_name=$(sed 's/.*name: //;s/,.*//' $CLASHDIR/proxies.yaml | grep -E "$exclude_name" | sed 's/.*: //;s/ /*/g') && exclude_name_name=$(echo $exclude_name_name | sed 's/ /\\\|/g;s/*/ /g') && sed -i "/\($exclude_name_name\)/d" $CLASHDIR/proxies.yaml $CLASHDIR/proxy-groups.yaml
				[ "$exclude_type" ] && exclude_type_name=$(sed 's/\(.*type: [^,]*\).*/\1/' $CLASHDIR/proxies.yaml | grep -E "type:.*$exclude_type" | awk -F , '{print $1}' | sed 's/.*: //;s/ /*/g;s/"//g;s/\[/\\\[/g') && exclude_type_name=$(echo $exclude_type_name | sed 's/ /\\\|/g;s/*/ /g') && sed -i "/\($exclude_type_name\)/d" $CLASHDIR/proxies.yaml $CLASHDIR/proxy-groups.yaml
				for startline in $(grep -nA1 proxies $CLASHDIR/proxy-groups.yaml | grep -vE "proxies|      -" | grep -oE [0-9]{1,5});do startlines="$startlines $(awk '/name/{flag=1} flag && NR<='$((startline-1))'{print NR$0; if (NR=='$((startline-1))') exit}' $CLASHDIR/proxy-groups.yaml | grep name | tail -1 | awk '{print $1}')";startlines_name="$startlines_name $(awk '/name/{flag=1} flag && NR<='$((startline-1))'{print NR$0; if (NR=='$((startline-1))') exit}' $CLASHDIR/proxy-groups.yaml | grep name | tail -1 | sed 's/.*name: //;s/.*: //;s/ /*/g')";done
				for stopline in $(grep -nA1 proxies $CLASHDIR/proxy-groups.yaml | grep -vE "proxies|      -" | grep -oE [0-9]{1,5});do stoplines="$stoplines $((stopline-1))";done
				sed -i '$d' $CLASHDIR/proxy-groups.yaml && lines=$(echo "$startlines $stoplines" | sort | awk '{for(i=1;i<=NF;i+=2) printf "-e %s,%sd ", $i, $(i+1)}') && [ "$lines" ] && sed -i $lines $CLASHDIR/proxy-groups.yaml && startlines_name=$(echo $startlines_name | sed 's/ /\\\|/g;s/*/ /g') && sed -i "/\($startlines_name\)/d" $CLASHDIR/proxy-groups.yaml
			}
			echo "proxies:" > $CLASHDIR/config_original.yaml && cat $CLASHDIR/proxies.yaml >> $CLASHDIR/config_original.yaml
			echo "proxy-groups:" >> $CLASHDIR/config_original.yaml && cat $CLASHDIR/proxy-groups.yaml $CLASHDIR/rules.yaml >> $CLASHDIR/config_original.yaml
			rm -f $CLASHDIR/config_original_temp_*.yaml $CLASHDIR/proxy-groups_temp_*.yaml $CLASHDIR/proxies.yaml $CLASHDIR/proxy-groups.yaml $CLASHDIR/rules.yaml
		else
			download "$CLASHDIR/config_original.yaml" "配置文件" "$sublink"
			[ $failedcount -eq 3 -a ! -f $CLASHDIR/config_original.yaml ] && {
				if [ -f $CLASHDIR/config_original.yaml.backup ];then
					echo -e "$YELLOW下载失败！即将尝试使用备份配置文件运行！$RESET"
					mv -f $CLASHDIR/config_original.yaml.backup $CLASHDIR/config_original.yaml && [ ! "$1" -o "$1" = "crontab" ] && update restore || update missingfiles;return 1
				else
					echo -e "$RED下载失败！已自动退出脚本$RESET" && exit
				fi
			}
		fi
	}
	[ ! -f $CLASHDIR/fake_ip_filter.list -a "$dns_mode" = "mixed" ] && {
		download "$CLASHDIR/fake_ip_filter.list" "fake-ip域名过滤列表文件" "https://raw.githubusercontent.com/juewuy/ShellCrash/dev/public/fake_ip_filter.list"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ ! -f $CLASHDIR/cn_ip.txt -a "$cnip_skip" = "开" ] && {
		download "$CLASHDIR/cn_ip.txt" "CN-IP数据库文件" "https://github.com/xilaochengv/Rule/releases/download/Latest/cn_ip.txt"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ ! -f $CLASHDIR/cn_ipv6.txt -a "$core_ipv6" = "开" -a "$cnipv6_skip" = "开" ] && {
		download "$CLASHDIR/cn_ipv6.txt" "CN-IPV6数据库文件" "https://github.com/xilaochengv/Rule/releases/download/Latest/cn_ipv6.txt"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ "$(grep -i geoip $CLASHDIR/config_original.yaml)" ] && [ ! -f $CLASHDIR/GeoIP.dat ] && {
		download "$CLASHDIR/GeoIP.dat" "GeoIP数据库文件" "$geoip_url" "true"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ "$(grep -i geosite $CLASHDIR/config_original.yaml)" -o "$dns_mode" = "mixed" ] && [ ! -f $CLASHDIR/GeoSite.dat ] && {
		download "$CLASHDIR/GeoSite.dat" "GeoSite数据库文件" "$geosite_url" "true"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ ! "$1" -o "$1" = "restore" -o "$1" = "crontab" ] && start
	return 0
}
startfirewall(){
	stopfirewall && update missingfiles
	iptables -w -t mangle -N Clash && [ "$redirect_mode" = "tproxy" ] || iptables -w -t nat -N Clash
	[ "$cnip_skip" = "开" ] && echo "create cn_ip hash:net" > /tmp/cn_ip.ipset && sed 's/.*/add cn_ip &/' $CLASHDIR/cn_ip.txt >> /tmp/cn_ip.ipset && ipset -! restore < /tmp/cn_ip.ipset && rm -f /tmp/cn_ip.ipset
	[ "$wanipv4" ] && {
		iptables -w -t mangle -A Clash -d $wanipv4 -m comment --comment "流量目标地址为本地WAN口IPv4地址，直接绕过Clash内核" -j RETURN
		[ "$redirect_mode" = "tproxy" ] || iptables -w -t nat -A Clash -d $wanipv4 -m comment --comment "流量目标地址为本地WAN口IPv4地址，直接绕过Clash内核" -j RETURN
	}
	[ ! "$dns_mode" = "fake-ip" -a ! "$dns_mode" = "mixed" ] && {
		iptables -w -t mangle -A Clash -d 198.18.0.1/16 -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
		[ "$redirect_mode" = "tproxy" ] || iptables -w -t nat -A Clash -d 198.18.0.1/16 -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
	}
	for ip in $routes;do
		iptables -w -t mangle -A Clash -d $ip -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
		[ "$redirect_mode" = "tproxy" ] || iptables -w -t nat -A Clash -d $ip -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
	done
	[ "$cnip_skip" = "开" ] && {
		iptables -w -t mangle -A Clash -m set --match-set cn_ip dst -m comment --comment "流量目的地为国内IPv4地址，直接绕过Clash内核" -j RETURN
		[ "$redirect_mode" = "tproxy" ] || iptables -w -t nat -A Clash -m set --match-set cn_ip dst -m comment --comment "流量目的地为国内IPv4地址，直接绕过Clash内核" -j RETURN
	}
	[ "$core_ipv6" = "开" ] && {
		ip6tables -w -t mangle -N Clash && [ "$redirect_mode" = "tproxy" ] || ip6tables -w -t nat -N Clash
		[ "$cnipv6_skip" = "开" ] && echo "create cn_ipv6 hash:net family inet6" > /tmp/cn_ipv6.ipset && sed 's/.*/add cn_ipv6 &/' $CLASHDIR/cn_ipv6.txt >> /tmp/cn_ipv6.ipset && ipset -! restore < /tmp/cn_ipv6.ipset && rm -f /tmp/cn_ipv6.ipset
		[ "$wanipv6" ] && {
			ip6tables -w -t mangle -A Clash -d $wanipv6 -m comment --comment "流量目标地址为本地WAN口IPv6地址，直接绕过Clash内核" -j RETURN
			[ "$redirect_mode" = "tproxy" ] || ip6tables -w -t nat -A Clash -d $wanipv6 -m comment --comment "流量目标地址为本地WAN口IPv6地址，直接绕过Clash内核" -j RETURN
		}
		for ip in $(ifconfig br-lan | grep -oE fe80.* | awk -F / '{print $1"/128"}') $routesv6;do
			ip6tables -w -t mangle -A Clash -d $ip -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
			[ "$redirect_mode" = "tproxy" ] || ip6tables -w -t nat -A Clash -d $ip -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
		done
		[ "$cnipv6_skip" = "开" ] && {
			ip6tables -w -t mangle -A Clash -m set --match-set cn_ipv6 dst -m comment --comment "流量目的地为国内IPv6地址，直接绕过Clash内核" -j RETURN
			[ "$redirect_mode" = "tproxy" ] || ip6tables -w -t nat -A Clash -m set --match-set cn_ipv6 dst -m comment --comment "流量目的地为国内IPv6地址，直接绕过Clash内核" -j RETURN
		}
	}
	[ "$dns_hijack" = "开" ] && {
		iptables -w -t nat -N Clash_DNS
		iptables -w -t nat -I PREROUTING -p udp --dport 53 -m comment --comment "DNS流量进入Clash_DNS规则链" -j Clash_DNS
		iptables -w -t nat -I OUTPUT -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash_DNS规则链" -j Clash_DNS
		iptables -w -t nat -A Clash_DNS -d $localip -p udp --dport 53 -m comment --comment "DNS流量进入Clash内核" -j REDIRECT --to-ports $dns_port
		iptables -w -t nat -A Clash_DNS -s 127.0.0.0/8 -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash内核" -j REDIRECT --to-ports $dns_port
	}
	[ "$dnsipv6_hijack" = "开" ] && {
		ip6tables -w -t nat -N Clash_DNS
		ip6tables -w -t nat -I PREROUTING -p udp --dport 53 -m comment --comment "DNS流量进入Clash_DNS规则链" -j Clash_DNS
		ip6tables -w -t nat -I OUTPUT -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash_DNS规则链" -j Clash_DNS
		ip6tables -w -t nat -A Clash_DNS -d $(ifconfig br-lan | grep -oE fe80.* | awk -F / '{print $1"/128"}') -p udp --dport 53 -m comment --comment "DNS流量进入Clash内核" -j REDIRECT --to-ports $dns_port
		ip6tables -w -t nat -A Clash_DNS -s ::1 -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash内核" -j REDIRECT --to-ports $dns_port
	}
	if [ "$common_ports" = "开" ];then
		ports="" && amount=0 && for port in $(echo $multiports | awk -F , '{for(i=1;i<=NF;i++){print $i};}');do
			[ "$(echo $port | grep -)" ] && port=$(echo $port | sed 's/-/:/') && let amount++
			[ $amount == 15 ] && {
				ports=$(echo $ports | sed 's/^,//')
				if [ "$redirect_mode" = "tproxy" ];then
					iptables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
					iptables -w -t mangle -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
					[ "$core_ipv6" = "开" ] && {
						ip6tables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
						ip6tables -w -t mangle -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
					}
				else
					iptables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
					iptables -w -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
					[ "$core_ipv6" = "开" ] && {
						ip6tables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
						ip6tables -w -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
					}
				fi
				amount=1 && ports=""
			}
			ports="$ports,$port" && let amount++
			[ $amount == 15 ] && {
				ports=$(echo $ports | sed 's/^,//')
				if [ "$redirect_mode" = "tproxy" ];then
					iptables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
					iptables -w -t mangle -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
					[ "$core_ipv6" = "开" ] && {
						ip6tables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
						ip6tables -w -t mangle -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
					}
				else
					iptables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
					iptables -w -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
					[ "$core_ipv6" = "开" ] && {
						ip6tables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
						ip6tables -w -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
					}
				fi
				amount=0 && ports=""
			}
		done
		[ "$ports" ] && {
			ports=$(echo $ports | sed 's/^,//')
			if [ "$redirect_mode" = "tproxy" ];then
				iptables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
				iptables -w -t mangle -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
				[ "$core_ipv6" = "开" ] && {
					ip6tables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
					ip6tables -w -t mangle -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
				}
			else
				iptables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
				iptables -w -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
				[ "$core_ipv6" = "开" ] && {
					ip6tables -w -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
					ip6tables -w -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
				}
			fi
		}
	else
		[ "$redirect_mode" = "tproxy" ] && iptables -w -t mangle -A PREROUTING -m comment --comment "流量进入Clash规则链" -j Clash || {
			iptables -w -t mangle -A PREROUTING -p udp -m comment --comment "udp流量进入Clash规则链" -j Clash
			iptables -w -t nat -A PREROUTING -p tcp -m comment --comment "tcp流量进入Clash规则链" -j Clash
		}
		[ "$core_ipv6" = "开" ] && {
			[ "$redirect_mode" = "tproxy" ] && ip6tables -w -t mangle -A PREROUTING -m comment --comment "流量进入Clash规则链" -j Clash || {
				ip6tables -w -t mangle -A PREROUTING -p udp -m comment --comment "udp流量进入Clash规则链" -j Clash
				ip6tables -w -t nat -A PREROUTING -p tcp -m comment --comment "tcp流量进入Clash规则链" -j Clash
			}
		}
	fi
	if [ "$redirect_mode" = "tproxy" ];then
		modprobe xt_TPROXY
		ip rule add fwmark $tproxy_port table 100
		ip route add local default dev lo table 100
		[ "$core_ipv6" = "开" ] && {
			ip -6 rule add fwmark $tproxy_port table 101
			ip -6 route add local default dev lo table 101
		}
	else
		ip route add default dev utun table 100
		ip rule add fwmark $redir_port table 100
		[ "$core_ipv6" = "开" ] && {
			ip -6 route add default dev utun table 101
			ip -6 rule add fwmark $redir_port table 101
		}
		iptables -w -I FORWARD -o utun -p udp -m comment --comment "utun出口udp流量允许放行" -j ACCEPT
		[ "$core_ipv6" = "开" ] && ip6tables -w -I FORWARD -o utun -p udp -m comment --comment "utun出口udp流量允许放行" -j ACCEPT
	fi
	[ "$mac_filter" = "开" ] && {
		if [ "$(grep -v '^ *#' $CLASHDIR/maclist.ini 2> /dev/null)" ];then
			while read LINE;do
				ip=$(echo $LINE | grep -v '^ *#' | awk '{print $1}' | grep '\.')
				mac=$(echo $LINE | grep -v '^ *#' | awk '{print $1}' | grep ':')
				device=$(echo $LINE | grep -v '^ *#' | awk '{for(i=2;i<=NF;i++){printf"%s ",$i};print out}' | sed 's/ $//');[ ! "$device" ] && device=设备名称未填写
				[ "$ip" ] && [ "$ip" != "$localip" ] && {
					if [ "$mac_filter_mode" = "白名单" ];then
						[ "$redirect_mode" = "tproxy" ] && {
							iptables -w -t mangle -A Clash -s $ip -p udp -m comment --comment "udp流量进入Clash内核（$device）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
							iptables -w -t mangle -A Clash -s $ip -p tcp -m comment --comment "tcp流量进入Clash内核（$device）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
						} || {
							iptables -w -t mangle -A Clash -s $ip -m comment --comment "流量进入Clash内核（$device）" -j MARK --set-mark $redir_port
							iptables -w -t nat -A Clash -s $ip -m comment --comment "流量进入Clash内核（$device）" -j REDIRECT --to-port $redir_port
						}
						[ "$core_ipv6" = "开" ] && echo -e "\n$BLUE$ip $RED加入ipv6防火墙白名单失败！（不支持使用ipv4地址进行添加，如有需要请将设备名单修改为mac地址）$RESET"
					else
						[ "$redirect_mode" = "tproxy" ] && iptables -w -t mangle -A Clash -s $ip -m comment --comment "流量禁止进入Clash内核（$device）" -j RETURN || {
							iptables -w -t mangle -A Clash -s $ip -m comment --comment "流量禁止进入Clash内核（$device）" -j RETURN
							iptables -w -t nat -A Clash -s $ip -m comment --comment "流量禁止进入Clash内核（$device）" -j RETURN
						}
						[ "$core_ipv6" = "开" ] && echo -e "\n$BLUE$ip $RED加入ipv6防火墙黑名单失败！（不支持使用ipv4地址进行添加，如有需要请将设备名单修改为mac地址）$RESET"
					fi
				}
				[ "$mac" ] && {
					if [ "$mac_filter_mode" = "白名单" ];then
						if [ "$redirect_mode" = "tproxy" ];then
							iptables -w -t mangle -A Clash -m mac --mac-source $mac -p udp -m comment --comment "udp流量进入Clash内核（$device）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
							iptables -w -t mangle -A Clash -m mac --mac-source $mac -p tcp -m comment --comment "tcp流量进入Clash内核（$device）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
							[ "$core_ipv6" = "开" ] && {
								ip6tables -w -t mangle -A Clash -m mac --mac-source $mac -p udp -m comment --comment "udp流量进入Clash内核（$device）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
								ip6tables -w -t mangle -A Clash -m mac --mac-source $mac -p tcp -m comment --comment "tcp流量进入Clash内核（$device）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
							}
						else
							iptables -w -t mangle -A Clash -m mac --mac-source $mac -m comment --comment "流量进入Clash内核（$device）" -j MARK --set-mark $redir_port
							iptables -w -t nat -A Clash -m mac --mac-source $mac -p tcp -m comment --comment "tcp流量进入Clash内核（$device）" -j REDIRECT --to-port $redir_port
							[ "$core_ipv6" = "开" ] && {
								ip6tables -w -t mangle -A Clash -m mac --mac-source $mac -m comment --comment "流量进入Clash内核（$device）" -j MARK --set-mark $redir_port
								ip6tables -w -t nat -A Clash -m mac --mac-source $mac -p tcp -m comment --comment "tcp流量进入Clash内核（$device）" -j REDIRECT --to-port $redir_port
							}
						fi
					else
						iptables -w -t mangle -A Clash -m mac --mac-source $mac -m comment --comment "流量禁止进入Clash内核（$device）" -j RETURN
						[ "$core_ipv6" = "开" ] && ip6tables -w -t mangle -A Clash -m mac --mac-source $mac -m comment --comment "流量禁止进入Clash内核（$device）" -j RETURN
						[ "$redirect_mode" = "tproxy" ] || {
							iptables -w -t nat -A Clash -m mac --mac-source $mac -m comment --comment "流量禁止进入Clash内核（$device）" -j RETURN
							[ "$core_ipv6" = "开" ] && ip6tables -w -t nat -A Clash -m mac --mac-source $mac -m comment --comment "流量禁止进入Clash内核（$device）" -j RETURN
						}
					fi
				}
			done < $CLASHDIR/maclist.ini
		else
			[ -s $CLASHDIR/maclist.ini ] || echo -e "#黑白名单列表（可填IP或MAC地址）\n#192.168.1.100\t我的电脑\n#aa:bb:cc:dd:ee:ff\t设备名称（可填可不填）" > $CLASHDIR/maclist.ini
			echo -e "\n$RED常用设备名单无内容！请配置 $BLUE$CLASHDIR/maclist.ini$RED 文件！$RESET" && sleep 2
		fi
	}
	[ "$mac_filter" != "开" -o "$mac_filter_mode" != "白名单" ] && {
		if [ "$redirect_mode" = "tproxy" ];then
			iptables -w -t mangle -A Clash -s $route -p udp -m comment --comment "udp流量进入Clash内核（$route网段）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
			iptables -w -t mangle -A Clash -s $route -p tcp -m comment --comment "tcp流量进入Clash内核（$route网段）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
			[ "$core_ipv6" = "开" ] && {
				for route6 in $routev6;do
					ip6tables -w -t mangle -A Clash -s $route6 -p udp -m comment --comment "udp流量进入Clash内核（$route6网段）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
					ip6tables -w -t mangle -A Clash -s $route6 -p tcp -m comment --comment "tcp流量进入Clash内核（$route6网段）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
				done
			}
		else
			iptables -w -t mangle -A Clash -s $route -m comment --comment "流量进入Clash内核（$route网段）" -j MARK --set-mark $redir_port
			iptables -w -t nat -A Clash -s $route -m comment --comment "流量进入Clash内核（$route网段）" -j REDIRECT --to-port $redir_port
			[ "$core_ipv6" = "开" ] && {
				for route6 in $routev6;do
					ip6tables -w -t mangle -A Clash -s $route6 -m comment --comment "流量进入Clash内核（$route6网段）" -j MARK --set-mark $redir_port
					ip6tables -w -t nat -A Clash -s $route6 -m comment --comment "流量进入Clash内核（$route6网段）" -j REDIRECT --to-port $redir_port
				done
			}
		fi
	}
	[ "$Docker_Proxy" = "开" ] && [ "$(ip route | grep docker | awk '{print $1}' | head -1)" ] && {
		route_docker=$(ip route | grep docker | awk '{print $1}' | head -1)
		route_dockerv6=$(ip -6 route | grep docker | awk '{print $1}')
		if [ "$redirect_mode" = "tproxy" ];then
			iptables -w -t mangle -A Clash -s $route_docker -p udp -m comment --comment "udp流量进入Clash内核（$route_docker网段）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
			iptables -w -t mangle -A Clash -s $route_docker -p tcp -m comment --comment "tcp流量进入Clash内核（$route_docker网段）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
			[ "$core_ipv6" = "开" ] && {
				for route_docker6 in $route_dockerv6;do
					ip6tables -w -t mangle -A Clash -s $route_docker6 -p udp -m comment --comment "udp流量进入Clash内核（$route_docker6网段）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
					ip6tables -w -t mangle -A Clash -s $route_docker6 -p tcp -m comment --comment "tcp流量进入Clash内核（$route_docker6网段）" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
				done
			}
		else
			iptables -w -t mangle -A Clash -s $route_docker -m comment --comment "流量进入Clash内核（$route_docker网段）" -j MARK --set-mark $redir_port
			iptables -w -t nat -A Clash -s $route_docker -m comment --comment "流量进入Clash内核（$route_docker网段）" -j REDIRECT --to-port $redir_port
			[ "$core_ipv6" = "开" ] && {
				for route_docker6 in $route_dockerv6;do
					ip6tables -w -t mangle -A Clash -s $route_docker6 -m comment --comment "流量进入Clash内核（$route_docker6网段）" -j MARK --set-mark $redir_port
					ip6tables -w -t nat -A Clash -s $route_docker6 -m comment --comment "流量进入Clash内核（$route_docker6网段）" -j REDIRECT --to-port $redir_port
				done
			}
		fi
	}
	[ "$wanipv4" -a "$Clash_Local_Proxy" = "开" ] && {
		iptables -w -t mangle -N Clash_Local_Proxy
		[ "$redirect_mode" = "tproxy" ] && iptables -w -t mangle -N Clash_Local_Proxy_PREROUTING || iptables -w -t nat -N Clash_Local_Proxy
		[ "$core_ipv6" = "开" ] && {
			ip6tables -w -t mangle -N Clash_Local_Proxy
			[ "$redirect_mode" = "tproxy" ] && ip6tables -w -t mangle -N Clash_Local_Proxy_PREROUTING || ip6tables -w -t nat -N Clash_Local_Proxy
		}
		if [ "$common_ports" = "开" ];then
			ports="" && amount=0 && for port in $(echo $multiports | awk -F , '{for(i=1;i<=NF;i++){print $i};}');do
				[ "$(echo $port | grep -)" ] && port=$(echo $port | sed 's/-/:/') && let amount++
				[ $amount == 15 ] && {
					ports=$(echo $ports | sed 's/^,//')
					iptables -w -t mangle -A OUTPUT -p udp -m multiport --dports $ports -m comment --comment "udp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					[ "$core_ipv6" = "开" ] && ip6tables -w -t mangle -A OUTPUT -p udp -m multiport --dports $ports -m comment --comment "udp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					if [ "$redirect_mode" = "tproxy" ];then
						iptables -w -t mangle -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
						[ "$core_ipv6" = "开" ] && ip6tables -w -t mangle -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					else
						iptables -w -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
						[ "$core_ipv6" = "开" ] && ip6tables -w -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					fi
					amount=1 && ports=""
				}
				ports="$ports,$port" && let amount++
				[ $amount == 15 ] && {
					ports=$(echo $ports | sed 's/^,//')
					iptables -w -t mangle -A OUTPUT -p udp -m multiport --dports $ports -m comment --comment "udp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					[ "$core_ipv6" = "开" ] && ip6tables -w -t mangle -A OUTPUT -p udp -m multiport --dports $ports -m comment --comment "udp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					if [ "$redirect_mode" = "tproxy" ];then
						iptables -w -t mangle -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
						[ "$core_ipv6" = "开" ] && ip6tables -w -t mangle -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					else
						iptables -w -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
						[ "$core_ipv6" = "开" ] && ip6tables -w -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					fi
					amount=1 && ports=""
				}
			done
			[ "$ports" ] && {
				ports=$(echo $ports | sed 's/^,//')
				iptables -w -t mangle -A OUTPUT -p udp -m multiport --dports $ports -m comment --comment "udp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
				[ "$core_ipv6" = "开" ] && ip6tables -w -t mangle -A OUTPUT -p udp -m multiport --dports $ports -m comment --comment "udp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
				if [ "$redirect_mode" = "tproxy" ];then
					iptables -w -t mangle -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					[ "$core_ipv6" = "开" ] && ip6tables -w -t mangle -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
				else
					iptables -w -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					[ "$core_ipv6" = "开" ] && ip6tables -w -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
				fi
			}
		else
			[ "$redirect_mode" = "tproxy" ] && iptables -w -t mangle -A OUTPUT -m comment --comment "本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy || {
				iptables -w -t mangle -A OUTPUT -p udp -m comment --comment "udp本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
				iptables -w -t nat -A OUTPUT -p tcp -m comment --comment "tcp本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
			}
			[ "$core_ipv6" = "开" ] && {
				[ "$redirect_mode" = "tproxy" ] && ip6tables -w -t mangle -A OUTPUT -m comment --comment "本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy || {
					ip6tables -w -t mangle -A OUTPUT -p udp -m comment --comment "udp本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					ip6tables -w -t nat -A OUTPUT -p tcp -m comment --comment "tcp本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
				}
			}
		fi
		iptables -w -t mangle -A Clash_Local_Proxy -m owner --gid-owner $redir_port -m comment --comment "Clash 本机流量防止回环" -j RETURN
		[ "$redirect_mode" = "tproxy" ] || iptables -w -t nat -A Clash_Local_Proxy -m owner --gid-owner $redir_port -m comment --comment "Clash 本机流量防止回环" -j RETURN
		[ ! "$dns_mode" = "fake-ip" -a ! "$dns_mode" = "mixed" ] && {
			iptables -w -t mangle -A Clash_Local_Proxy -d 198.18.0.1/16 -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
			[ "$redirect_mode" = "tproxy" ] || iptables -w -t nat -A Clash_Local_Proxy -d 198.18.0.1/16  -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
		}
		for ip in $routes;do
			iptables -w -t mangle -A Clash_Local_Proxy -d $ip -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
			[ "$redirect_mode" = "tproxy" ] || iptables -w -t nat -A Clash_Local_Proxy -d $ip -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
		done
		[ "$cnip_skip" = "开" ] && {
			iptables -w -t mangle -A Clash_Local_Proxy -m set --match-set cn_ip dst -m comment --comment "本机流量目的地为国内IPv4地址，直接绕过Clash内核" -j RETURN
			[ "$redirect_mode" = "tproxy" ] || iptables -w -t nat -A Clash_Local_Proxy -m set --match-set cn_ip dst -m comment --comment "本机流量目的地为国内IPv4地址，直接绕过Clash内核" -j RETURN
		}
		[ "$core_ipv6" = "开" ] && {
			ip6tables -w -t mangle -A Clash_Local_Proxy -m owner --gid-owner $redir_port -m comment --comment "Clash 本机流量防止回环" -j RETURN
			[ "$redirect_mode" = "tproxy" ] || ip6tables -w -t nat -A Clash_Local_Proxy -m owner --gid-owner $redir_port -m comment --comment "Clash 本机流量防止回环" -j RETURN
			for ip in $routesv6;do
				ip6tables -w -t mangle -A Clash_Local_Proxy -d $ip -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
				[ "$redirect_mode" = "tproxy" ] || ip6tables -w -t nat -A Clash_Local_Proxy -d $ip -m comment --comment "流量目的地为特殊IP网段，直接绕过Clash内核" -j RETURN
			done
			[ "$cnipv6_skip" = "开" ] && {
				ip6tables -w -t mangle -A Clash_Local_Proxy -m set --match-set cn_ipv6 dst -m comment --comment "本机流量目的地为国内IPv6地址，直接绕过Clash内核" -j RETURN
				[ "$redirect_mode" = "tproxy" ] || ip6tables -w -t nat -A Clash_Local_Proxy -m set --match-set cn_ipv6 dst -m comment --comment "本机流量目的地为国内IPv6地址，直接绕过Clash内核" -j RETURN
			}
		}
		if [ "$redirect_mode" = "tproxy" ];then
			iptables -w -t mangle -A Clash_Local_Proxy -s $wanipv4 -m comment --comment "本机流量标记" -j MARK --set-mark $tproxy_port
			iptables -w -t mangle -A PREROUTING -m mark --mark $tproxy_port -m comment --comment "本机流量进入Clash_Local_Proxy_PREROUTING规则链" -j Clash_Local_Proxy_PREROUTING
			iptables -w -t mangle -A Clash_Local_Proxy_PREROUTING -p udp -m comment --comment "udp本机流量进入Clash内核" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
			iptables -w -t mangle -A Clash_Local_Proxy_PREROUTING -p tcp -m comment --comment "tcp本机流量进入Clash内核" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
			[ "$wanipv6" -a "$core_ipv6" = "开" ] && {
				ip6tables -w -t mangle -A Clash_Local_Proxy -s $wanipv6 -m comment --comment "本机流量标记" -j MARK --set-mark $tproxy_port
				ip6tables -w -t mangle -A PREROUTING -m mark --mark $tproxy_port -m comment --comment "本机流量进入Clash_Local_Proxy_PREROUTING规则链" -j Clash_Local_Proxy_PREROUTING
				ip6tables -w -t mangle -A Clash_Local_Proxy_PREROUTING -p udp -m comment --comment "udp本机流量进入Clash内核" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
				ip6tables -w -t mangle -A Clash_Local_Proxy_PREROUTING -p tcp -m comment --comment "tcp本机流量进入Clash内核" -j TPROXY --on-port $tproxy_port --tproxy-mark $tproxy_port
			}
		else
			iptables -w -t mangle -A Clash_Local_Proxy -s $wanipv4 -m comment --comment "本机流量标记" -j MARK --set-mark $redir_port
			iptables -w -t nat -A Clash_Local_Proxy -s $wanipv4 -p tcp -m comment --comment "tcp本机流量进入Clash内核" -j REDIRECT --to-port $redir_port
			[ "$wanipv6" -a "$core_ipv6" = "开" ] && {
				ip6tables -w -t mangle -A Clash_Local_Proxy -s $wanipv6 -m comment --comment "本机流量标记" -j MARK --set-mark $redir_port
				ip6tables -w -t nat -A Clash_Local_Proxy -s $wanipv6 -p tcp -m comment --comment "tcp本机流量进入Clash内核" -j REDIRECT --to-port $redir_port
			}
		fi
	}
	return 0
}
stopfirewall(){
	while [ "$(iptables -w -t mangle -S PREROUTING | grep 流量进入Clash)" ];do eval iptables -w -t mangle $(iptables -w -t mangle -S PREROUTING | grep 流量进入Clash | sed 's/-A/-D/' | head -1) 2> /dev/null;done
	while [ "$(iptables -w -t mangle -S OUTPUT | grep 流量进入Clash)" ];do eval iptables -w -t mangle $(iptables -w -t mangle -S OUTPUT | grep 流量进入Clash | sed 's/-A/-D/' | head -1) 2> /dev/null;done
	while [ "$(iptables -w -t nat -S PREROUTING | grep 流量进入Clash)" ];do eval iptables -w -t nat $(iptables -w -t nat -S PREROUTING | grep 流量进入Clash | sed 's/-A/-D/' | head -1) 2> /dev/null;done
	while [ "$(iptables -w -t nat -S OUTPUT | grep 流量进入Clash)" ];do eval iptables -w -t nat $(iptables -w -t nat -S OUTPUT | grep 流量进入Clash | sed 's/-A/-D/' | head -1) 2> /dev/null;done
	iptables -w -D FORWARD -o utun -p udp -m comment --comment "utun出口udp流量允许放行" -j ACCEPT 2> /dev/null
	iptables -w -t mangle -F Clash 2> /dev/null
	iptables -w -t mangle -X Clash 2> /dev/null
	iptables -w -t mangle -F Clash_Local_Proxy 2> /dev/null
	iptables -w -t mangle -X Clash_Local_Proxy 2> /dev/null
	iptables -w -t mangle -F Clash_Local_Proxy_PREROUTING 2> /dev/null
	iptables -w -t mangle -X Clash_Local_Proxy_PREROUTING 2> /dev/null
	iptables -w -t nat -F Clash 2> /dev/null
	iptables -w -t nat -X Clash 2> /dev/null
	iptables -w -t nat -F Clash_DNS 2> /dev/null
	iptables -w -t nat -X Clash_DNS 2> /dev/null
	iptables -w -t nat -F Clash_Local_Proxy 2> /dev/null
	iptables -w -t nat -X Clash_Local_Proxy 2> /dev/null
	ip route del default dev utun table 100 2> /dev/null
	ip rule del fwmark $redir_port table 100 2> /dev/null
	ip rule del fwmark $tproxy_port table 100 2> /dev/null
	ip route del local default dev lo table 100 2> /dev/null
	ipset -q destroy cn_ip
	while [ "$(ip6tables -w -t mangle -S PREROUTING | grep 流量进入Clash)" ];do eval ip6tables -w -t mangle $(ip6tables -w -t mangle -S PREROUTING | grep 流量进入Clash | sed 's/-A/-D/' | head -1) 2> /dev/null;done
	while [ "$(ip6tables -w -t mangle -S OUTPUT | grep 流量进入Clash)" ];do eval ip6tables -w -t mangle $(ip6tables -w -t mangle -S OUTPUT | grep 流量进入Clash | sed 's/-A/-D/' | head -1) 2> /dev/null;done
	while [ "$(ip6tables -w -t nat -S PREROUTING | grep 流量进入Clash)" ];do eval ip6tables -w -t nat $(ip6tables -w -t nat -S PREROUTING | grep 流量进入Clash | sed 's/-A/-D/' | head -1) 2> /dev/null;done
	while [ "$(ip6tables -w -t nat -S OUTPUT | grep 流量进入Clash)" ];do eval ip6tables -w -t nat $(ip6tables -w -t nat -S OUTPUT | grep 流量进入Clash | sed 's/-A/-D/' | head -1) 2> /dev/null;done
	ip6tables -w -D FORWARD -o utun -p udp -m comment --comment "utun出口udp流量允许放行" -j ACCEPT 2> /dev/null
	ip6tables -w -t mangle -F Clash 2> /dev/null
	ip6tables -w -t mangle -X Clash 2> /dev/null
	ip6tables -w -t mangle -F Clash_Local_Proxy 2> /dev/null
	ip6tables -w -t mangle -X Clash_Local_Proxy 2> /dev/null
	ip6tables -w -t mangle -F Clash_Local_Proxy_PREROUTING 2> /dev/null
	ip6tables -w -t mangle -X Clash_Local_Proxy_PREROUTING 2> /dev/null
	ip6tables -w -t nat -F Clash 2> /dev/null
	ip6tables -w -t nat -X Clash 2> /dev/null
	ip6tables -w -t nat -F Clash_DNS 2> /dev/null
	ip6tables -w -t nat -X Clash_DNS 2> /dev/null
	ip6tables -w -t nat -F Clash_Local_Proxy 2> /dev/null
	ip6tables -w -t nat -X Clash_Local_Proxy 2> /dev/null
	ip -6 route del default dev utun table 101 2> /dev/null
	ip -6 rule del fwmark $redir_port table 101 2> /dev/null
	ip -6 rule del fwmark $tproxy_port table 101 2> /dev/null
	ip -6 route del local default dev lo table 101 2> /dev/null
	ipset -q destroy cn_ipv6
	rmmod xt_TPROXY 2> /dev/null
	return 0
}
showfirewall(){
	echo -e "------------------------------------------MANGLE------------------------------------------" && {
		[ "$(iptables -w -t mangle -S PREROUTING | grep Clash)" ] && iptables -w -t mangle -nvL PREROUTING && echo && iptables -w -t mangle -nvL Clash
		[ "$(iptables -w -t mangle -S PREROUTING | grep Clash_Local_Proxy_PREROUTING)" ] && echo && iptables -w -t mangle -nvL Clash_Local_Proxy_PREROUTING
		[ "$(iptables -w -t mangle -S OUTPUT | grep Clash_Local_Proxy)" ] && echo && iptables -w -t mangle -nvL OUTPUT && echo && iptables -w -t mangle -nvL Clash_Local_Proxy
	}
	echo -e "\n-------------------------------------------NAT--------------------------------------------" && {
		[ "$(iptables -w -t nat -S PREROUTING | grep Clash)" ] && iptables -w -t nat -nvL PREROUTING
		[ "$(iptables -w -t nat -S Clash 2> /dev/null)" ] && echo && iptables -w -t nat -nvL Clash
		[ "$(iptables -w -t nat -S OUTPUT | grep Clash)" ] && echo && iptables -w -t nat -nvL OUTPUT && {
			[ "$(iptables -w -t nat -S OUTPUT | grep Clash_DNS)" ] && echo && iptables -w -t nat -nvL Clash_DNS
			[ "$(iptables -w -t nat -S OUTPUT | grep Clash_Local_Proxy)" ] && echo && iptables -w -t nat -nvL Clash_Local_Proxy
		}
	}
	echo -e "\n------------------------------------------FILTER------------------------------------------" && {
		[ "$(iptables -w -S FORWARD | grep utun)" ] && iptables -w -nvL FORWARD
	}
	[ "$routev6" ] && {
		echo -e "\n---------------------------------------IPv6  MANGLE---------------------------------------" && {
			[ "$(ip6tables -w -t mangle -S PREROUTING | grep Clash)" ] && ip6tables -w -t mangle -nvL PREROUTING && echo && ip6tables -w -t mangle -nvL Clash
			[ "$(ip6tables -w -t mangle -S PREROUTING | grep Clash_Local_Proxy_PREROUTING)" ] && echo && ip6tables -w -t mangle -nvL Clash_Local_Proxy_PREROUTING
			[ "$(ip6tables -w -t mangle -S OUTPUT | grep Clash_Local_Proxy)" ] && echo && ip6tables -w -t mangle -nvL OUTPUT && echo && ip6tables -w -t mangle -nvL Clash_Local_Proxy
		}
		echo -e "\n----------------------------------------IPv6  NAT-----------------------------------------" && {
			[ "$(ip6tables -w -t nat -S PREROUTING | grep Clash)" ] && ip6tables -w -t nat -nvL PREROUTING
			[ "$(ip6tables -w -t nat -S Clash 2> /dev/null)" ] && echo && ip6tables -w -t nat -nvL Clash
			[ "$(ip6tables -w -t nat -S OUTPUT | grep Clash)" ] && echo && ip6tables -w -t nat -nvL OUTPUT && {
				[ "$(ip6tables -w -t nat -S OUTPUT | grep Clash_DNS)" ] && echo && ip6tables -w -t nat -nvL Clash_DNS
				[ "$(ip6tables -w -t nat -S OUTPUT | grep Clash_Local_Proxy)" ] && echo && ip6tables -w -t nat -nvL Clash_Local_Proxy
			}
		}
		echo -e "\n---------------------------------------IPv6  FILTER---------------------------------------" && {
			[ "$(ip6tables -w -S FORWARD | grep utun)" ] && ip6tables -w -nvL FORWARD
		}
	}
	return 0
}
#修复小米AX9000开启QOS时若Clash-mihomo正在运行而导致某些特定udp端口流量（如80 8080等）无法通过问题
[ "$(uci get /usr/share/xiaoqiang/xiaoqiang_version.version.HARDWARE 2> /dev/null)" = "RA70" ] && \
sed -i "s@\[ -d /sys/module/shortcut_fe_cm ] |@\[ -d /sys/module/shortcut_fe_cm -o -n \"\$(pidof mihomo)\" ] |@" /etc/init.d/shortcut-fe
main(){
	saveconfig && num="$1" && confignum=$2 && [ ! "$num" ] && echo && {
		[ ! "$showed" ] && echo -e "$YELLOW作者自用 ${BLUE}Clash-mihomo $YELLOW脚本，制作基于网络：${SKYBLUE}PPPoE拨号上网$YELLOW，路由器型号：$SKYBLUE小米AX9000（RA70）$RESET\n" && showed=true
		echo "========================================================="
		echo "请输入你的选项："
		echo "---------------------------------------------------------"
		[ -s $CLASHDIR/starttime -a "$(pidof mihomo)" ] && states="$PINK$(awk BEGIN'{printf "%0.2f MB",'$(cat /proc/$(pidof mihomo)/status 2> /dev/null | grep -w VmRSS | awk '{print $2}')'/1024}')" || states="$RED已停止"
		echo -e "1.  $GREEN重新启动  ${BLUE}Clash-mihomo$RESET\t\t$YELLOW运存占用：$states$RESET"
		if [ -s $CLASHDIR/starttime -a "$(pidof mihomo)" ];then
			TotalSeconeds=$(($(date +%s)-$(cat $CLASHDIR/starttime)))
			Days=$(awk BEGIN'{printf "%d",'$TotalSeconeds'/60/60/24}') && [ "$Days" -gt 0 ] && Days=$Days天 || Days=""
			Hours=$(awk BEGIN'{printf "%d\n",'$TotalSeconeds'/60/60%24}') && [ "$Hours" -gt 0 ] && Hours=$Hours小时 || Hours=""
			Minutes=$(awk BEGIN'{printf "%d\n",'$TotalSeconeds'/60%60}') && [ "$Minutes" -gt 0 ] && Minutes=$Minutes分 || Minutes=""
			Seconeds=$(awk BEGIN'{printf "%d\n",'$TotalSeconeds'%60}')秒
			states="$YELLOW运行时长：$PINK$Days$Hours$Minutes$Seconeds"
		else states="";fi
		echo -e "2.  $RED停止运行  ${BLUE}Clash-mihomo$RESET\t\t$states$RESET"
		echo -e "3.  $YELLOW修     改 $SKYBLUE内核相关配置$RESET"
		[ "$mac_filter" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "4.  $GREEN开启$RESET/$RED关闭 $SKYBLUE常用设备过滤\t\t$YELLOW当前状态：$states$RESET"
		[ "$Clash_Local_Proxy" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "5.  $GREEN开启$RESET/$RED关闭 $SKYBLUE本机流量代理\t\t$YELLOW当前状态：$states$RESET"
		[ "$dns_hijack" = "开" -o "$dnsipv6_hijack" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "6.  $GREEN开启$RESET/$RED关闭 ${SKYBLUE}DNS流量劫持\t\t$YELLOW当前状态：$states$RESET"
		[ "$common_ports" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "7.  $GREEN开启$RESET/$RED关闭 $SKYBLUE仅代理常用端口\t\t$YELLOW当前状态：$states$RESET"
		[ "$cnip_skip" = "开" -o "$cnipv6_skip" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "8.  $GREEN开启$RESET/$RED关闭 ${SKYBLUE}CNIP绕过内核\t\t$YELLOW当前状态：$states$RESET"
		[ "$Docker_Proxy" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "9.  $GREEN开启$RESET/$RED关闭 ${SKYBLUE}Docker流量代理\t\t$YELLOW当前状态：$states$RESET"
		echo -e "10. $YELLOW查     看 $SKYBLUE防火墙相关规则$RESET"
		[ "$config_url" ] && [ "$(grep $config_url$ $CLASHDIR/config_url.ini)" ] && states="$BLUE$(grep $config_url$ $CLASHDIR/config_url.ini | sed 's/ http.*//')" || states="$SKYBLUE$config_url"
		echo -e "11. $YELLOW更     新 $SKYBLUE订阅配置文件\t\t$YELLOW当前规则：$states$RESET"
		echo -e "12. $YELLOW更     新 $SKYBLUE所有相关文件$RESET"
		[ "$(grep "$0 start$" /etc/rc.d/S99Clash_mihomo 2> /dev/null)" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "13. $GREEN开启$RESET/$RED关闭 $SKYBLUE开机自启动\t\t$YELLOW当前状态：$states$RESET"
		echo -e "88. $RED一键卸载  ${BLUE}Clash-mihomo $RED所有文件$RESET"
		echo "---------------------------------------------------------"
		echo && read -p "请输入对应选项的数字 > " num
	}
	case "$num" in
		1)
			start;;
		2)
			stop;;
		3)
			[ ! "$confignum" ] && {
				echo "========================================================="
				echo "请输入你的选项："
				echo "---------------------------------------------------------"
				[ "$redirect_mode" = "tproxy" ] && states="TPROXY" || states="mixed$RESET（${BLUE}REDIRECT $RESET+ ${BLUE}utun$RESET）"
				echo -e "1. $YELLOW切     换 $SKYBLUE流量代理模式\t\t$YELLOW当前模式：$BLUE$states$RESET"
				echo -e "2. $YELLOW修     改 ${SKYBLUE}DNS解析模式\t\t$YELLOW当前模式：${BLUE}$dns_mode$RESET"
				echo -e "3. $YELLOW修     改 $SKYBLUE透明代理端口\t\t$YELLOW当前端口：${BLUE}$redir_port$RESET"
				echo -e "4. $YELLOW修     改 $SKYBLUE混合代理端口\t\t$YELLOW当前端口：${BLUE}$mixed_port$RESET"
				echo -e "5. $YELLOW修     改 ${SKYBLUE}TPROXY透明代理端口\t\t$YELLOW当前端口：${BLUE}$tproxy_port$RESET"
				echo -e "6. $YELLOW修     改 ${SKYBLUE}DNS服务监听端口\t\t$YELLOW当前端口：${BLUE}$dns_port$RESET"
				echo -e "7. $YELLOW修     改 ${SKYBLUE}网页UI面板监听端口\t\t$YELLOW当前端口：${BLUE}$dashboard_port$RESET"
				echo -e "8. $YELLOW修     改 ${SKYBLUE}访问内核验证用户名\t\t$YELLOW当前名称：${BLUE}$authusername$RESET"
				echo -e "9. $YELLOW修     改 ${SKYBLUE}访问内核验证密码\t\t$YELLOW当前密码：${BLUE}$authpassword$RESET"
				[ "$core_ipv6" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
				echo -e "10.$GREEN开启$RESET/$RED关闭 ${SKYBLUE}IPv6流量代理\t\t$YELLOW当前状态：${BLUE}$states$RESET"
				[ "$dns_ipv6" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
				echo -e "11.$GREEN开启$RESET/$RED关闭 ${SKYBLUE}IPv6 DNS解析\t\t$YELLOW当前状态：${BLUE}$states$RESET"
				echo -e "12.$YELLOW修     改 $SKYBLUE默认DNS解析服务器\t\t$YELLOW正在使用：${BLUE}$dns_default$RESET" | sed 's/, /,/g'
				echo -e "13.$YELLOW修     改 $SKYBLUE海外DNS解析服务器\t\t$YELLOW正在使用：${BLUE}$dns_oversea$RESET" | sed 's/, /,/g'
				echo "---------------------------------------------------------"
				echo "0. 返回上一页"
				echo && read -p "请输入对应选项的数字 > " confignum
			}
			[ "$(pidof mihomo)" ] && [ "$confignum" -a ! "$(echo $confignum | sed 's/[1-9]//g')" ] && [ $confignum -le 13 ] && {
				echo "========================================================="
				echo -e "${BLUE}Clash-mihomo $YELLOW正在运行中！修改前需要先停止运行 ${BLUE}Clash-mihomo $YELLOW！$RESET"
				echo "---------------------------------------------------------"
				echo "1. 确认停止运行并修改"
				echo "---------------------------------------------------------"
				echo "0. 返回上一页"
				echo && read -p "请输入对应选项的数字 > " mihomonum && [ "$mihomonum" = "1" ] && stop || { [ "$mihomonum" = "0" ] && main $num || exit; }
			}
			case "$confignum" in
				1)
					[ "$redirect_mode" = "tproxy" ] && redirect_mode=mixed || { modprobe xt_TPROXY 2> /dev/null && redirect_mode=tproxy && rmmod xt_TPROXY || echo -e "\n${BLUE}TPROXY $RED内核模块不存在，无法切换！$RESET"; };main $num;;
				2)
					echo "========================================================="
					echo "请输入你的选项："
					echo "---------------------------------------------------------"
					echo -e "1. $YELLOW修     改 ${SKYBLUE}DNS解析模式：${BLUE}redir-host$RESET"
					echo -e "2. $YELLOW修     改 ${SKYBLUE}DNS解析模式：${BLUE}mixed$YELLOW（海外fake-ip国内real-ip）$RESET"
					echo -e "3. $YELLOW修     改 ${SKYBLUE}DNS解析模式：${BLUE}fake-ip$YELLOW（域名访问时，CNIP绕过内核功能失效）$RESET"
					echo "---------------------------------------------------------"
					echo "0. 返回上一页"
					echo && read -p "请输入对应选项的数字 > " configdnsmodenum
					case "$configdnsmodenum" in
						1)
							dns_mode=redir-host;main $num;;
						2)
							dns_mode=mixed;main $num;;
						3)
							dns_mode=fake-ip;main $num;;
						0)
							main $num;;
					esac;;
				3)
					echo && read -p "请输入透明代理端口：" redir_port_temp
					[ "$redir_port_temp" ] && if [ "$redir_port_temp" = "0" ];then
						main $num
					elif [ "$(echo $redir_port_temp | sed 's/[0-9]//g')" ];then
						echo -e "\n$YELLOW请输入正确的端口！$RESET" && sleep 1 && main $num
					else
						if [ $redir_port_temp -gt 65535 ];then
							echo -e "\n$YELLOW请输入正确的端口！$RESET" && sleep 1 && main $num
						else
							processtcp=$(netstat -lnWp | grep tcp | grep ":$redir_port_temp " | awk '{print $NF}' | sed 's/.*\///' | head -1) && [ "$processtcp" ] && processtcp="tcp端口已被 $BLUE$processtcp $RED占用！"
							processudp=$(netstat -lnWp | grep udp | grep ":$redir_port_temp " | awk '{print $NF}' | sed 's/.*\///' | head -1) && [ "$processudp" ] && processudp="udp端口已被 $BLUE$processudp $RED占用！"
							if [ ! "$processtcp" -a ! "$processudp" ];then
								redir_port=$redir_port_temp && main $num
							else
								echo -e "\n$RED检测到 $PINK$redir_port_temp $RED$processtcp$processudp修改失败！$RESET" && sleep 1 && main $num
							fi
						fi
					fi;;
				4)
					echo && read -p "请输入混合代理端口：" mixed_port_temp
					[ "$mixed_port_temp" ] && if [ "$mixed_port_temp" = "0" ];then
						main $num
					elif [ "$(echo $mixed_port_temp | sed 's/[0-9]//g')" ];then
						echo -e "\n$YELLOW请输入正确的端口！$RESET" && sleep 1 && main $num
					else
						if [ $mixed_port_temp -gt 65535 ];then
							echo -e "\n$YELLOW请输入正确的端口！$RESET" && sleep 1 && main $num
						else
							processtcp=$(netstat -lnWp | grep tcp | grep ":$mixed_port_temp " | awk '{print $NF}' | sed 's/.*\///' | head -1) && [ "$processtcp" ] && processtcp="tcp端口已被 $BLUE$processtcp $RED占用！"
							processudp=$(netstat -lnWp | grep udp | grep ":$mixed_port_temp " | awk '{print $NF}' | sed 's/.*\///' | head -1) && [ "$processudp" ] && processudp="udp端口已被 $BLUE$processudp $RED占用！"
							if [ ! "$processtcp" -a ! "$processudp" ];then
								mixed_port=$mixed_port_temp && main $num
							else
								echo -e "\n$RED检测到 $PINK$mixed_port_temp $RED$processtcp$processudp修改失败！$RESET" && sleep 1 && main $num
							fi
						fi
					fi;;
				5)
					echo && read -p "请输入TPROXY透明代理端口：" tproxy_port_temp
					[ "$tproxy_port_temp" ] && if [ "$tproxy_port_temp" = "0" ];then
						main $num
					elif [ "$(echo $tproxy_port_temp | sed 's/[0-9]//g')" ];then
						echo -e "\n$YELLOW请输入正确的端口！$RESET" && sleep 1 && main $num
					else
						if [ $tproxy_port_temp -gt 65535 ];then
							echo -e "\n$YELLOW请输入正确的端口！$RESET" && sleep 1 && main $num
						else
							processtcp=$(netstat -lnWp | grep tcp | grep ":$tproxy_port_temp " | awk '{print $NF}' | sed 's/.*\///' | head -1) && [ "$processtcp" ] && processtcp="tcp端口已被 $BLUE$processtcp $RED占用！"
							processudp=$(netstat -lnWp | grep udp | grep ":$tproxy_port_temp " | awk '{print $NF}' | sed 's/.*\///' | head -1) && [ "$processudp" ] && processudp="udp端口已被 $BLUE$processudp $RED占用！"
							if [ ! "$processtcp" -a ! "$processudp" ];then
								tproxy_port=$tproxy_port_temp && main $num
							else
								echo -e "\n$RED检测到 $PINK$tproxy_port_temp $RED$processtcp$processudp修改失败！$RESET" && sleep 1 && main $num
							fi
						fi
					fi;;
				6)
					echo && read -p "请输入DNS服务监听端口：" dns_port_temp
					[ "$dns_port_temp" ] && if [ "$dns_port_temp" = "0" ];then
						main $num
					elif [ "$(echo $dns_port_temp | sed 's/[0-9]//g')" ];then
						echo -e "\n$YELLOW请输入正确的端口！$RESET" && sleep 1 && main $num
					else
						if [ $dns_port_temp -gt 65535 ];then
							echo -e "\n$YELLOW请输入正确的端口！$RESET" && sleep 1 && main $num
						else
							processtcp=$(netstat -lnWp | grep tcp | grep ":$dns_port_temp " | awk '{print $NF}' | sed 's/.*\///' | head -1) && [ "$processtcp" ] && processtcp="tcp端口已被 $BLUE$processtcp $RED占用！"
							processudp=$(netstat -lnWp | grep udp | grep ":$dns_port_temp " | awk '{print $NF}' | sed 's/.*\///' | head -1) && [ "$processudp" ] && processudp="udp端口已被 $BLUE$processudp $RED占用！"
							if [ ! "$processtcp" -a ! "$processudp" ];then
								dns_port=$dns_port_temp && main $num
							else
								echo -e "\n$RED检测到 $PINK$dns_port_temp $RED$processtcp$processudp修改失败！$RESET" && sleep 1 && main $num
							fi
						fi
					fi;;
				7)
					echo && read -p "请输入网页UI面板监听端口：" dashboard_port_temp
					[ "$dashboard_port_temp" ] && if [ "$dashboard_port_temp" = "0" ];then
						main $num
					elif [ "$(echo $dashboard_port_temp | sed 's/[0-9]//g')" ];then
						echo -e "\n$YELLOW请输入正确的端口！$RESET" && sleep 1 && main $num
					else
						if [ $dashboard_port_temp -gt 65535 ];then
							echo -e "\n$YELLOW请输入正确的端口！$RESET" && sleep 1 && main $num
						else
							processtcp=$(netstat -lnWp | grep tcp | grep ":$dashboard_port_temp " | awk '{print $NF}' | sed 's/.*\///' | head -1) && [ "$processtcp" ] && processtcp="tcp端口已被 $BLUE$processtcp $RED占用！"
							if [ ! "$processtcp" ];then
								dashboard_port=$dashboard_port_temp && main $num
							else
								echo -e "\n$RED检测到 $PINK$dashboard_port_temp $RED$processtcp修改失败！$RESET" && sleep 1 && main $num
							fi
						fi
					fi;;
				8)
					echo && read -p "请输入访问内核验证用户名：" authusername_temp
					authusername=$(echo $authusername_temp | awk '{print $1}' | sed 's/[^ -~]//g') && main $num;;
				9)
					echo && read -p "请输入访问内核验证密码：" authpassword_temp
					authpassword=$(echo $authpassword_temp | awk '{print $1}' | sed 's/[^ -~]//g') && main $num;;
				10)
					[ "$core_ipv6" = "开" ] && core_ipv6=关 || core_ipv6=开;main $num;;
				11)
					[ "$dns_ipv6" = "开" ] && dns_ipv6=关 || dns_ipv6=开;main $num;;
				12)
					echo && read -p "请输入默认DNS解析服务器（如有多个请用逗号‘,’隔开）：" dns_default_temp
					[ "$dns_default_temp" = "0" ] && main $num || { [ "$dns_default_temp" ] && dns_default=$(echo $dns_default_temp | awk '{print $1}' | sed 's/,*$// | sed 's/[^ -~]//g'') && main $num; };;
				13)
					echo && read -p "请输入默认DNS解析服务器（如有多个请用逗号‘,’隔开）：" dns_oversea_temp
					[ "$dns_oversea_temp" = "0" ] && main $num || { [ "$dns_oversea_temp" ] && dns_oversea=$(echo $dns_oversea_temp | awk '{print $1}' | sed 's/[^ -~]//g' | sed 's/,*$//') && main $num; };;
				0)
					main;;
			esac;;
		4)
			echo "========================================================="
			echo "请输入你的选项："
			echo "---------------------------------------------------------"
			[ "$mac_filter" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
			echo -e "1. $GREEN开启$RESET/$RED关闭 $SKYBLUE常用设备过滤\t\t$YELLOW当前状态：$states$RESET"
			[ "$mac_filter_mode" = "黑名单" ] && states="$PINK黑名单" || states="$GREEN白名单"
			echo -e "2. $YELLOW切     换 $SKYBLUE常用设备过滤模式\t\t$YELLOW当前状态：$states$RESET"
			echo "---------------------------------------------------------"
			echo "0. 返回上一页"
			echo && read -p "请输入对应选项的数字 > " confignum
			case "$confignum" in
				1)
					[ "$mac_filter" = "开" ] && mac_filter=关 || mac_filter=开
					[ "$(pidof mihomo)" ] && startfirewall;main $num;;
				2)
					[ "$mac_filter_mode" = "黑名单" ] && mac_filter_mode=白名单 || mac_filter_mode=黑名单
					[ "$(pidof mihomo)" ] && startfirewall;main $num;;
				0)
					main;;
			esac;;
		5)
			[ "$Clash_Local_Proxy" = "开" ] && Clash_Local_Proxy=关 || Clash_Local_Proxy=开
			[ "$(pidof mihomo)" ] && startfirewall;main;;
		6)
			echo "========================================================="
			echo "请输入你的选项："
			echo "---------------------------------------------------------"
			[ "$dns_hijack" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
			echo -e "1. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}DNS IPv4流量劫持\t\t$YELLOW当前状态：$states$RESET"
			[ "$dnsipv6_hijack" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
			echo -e "2. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}DNS IPv6流量劫持\t\t$YELLOW当前状态：$states$RESET"
			echo "---------------------------------------------------------"
			echo "0. 返回上一页"
			echo && read -p "请输入对应选项的数字 > " confignum
			case "$confignum" in
				1)
					[ "$dns_hijack" = "开" ] && dns_hijack=关 || dns_hijack=开
					[ "$(pidof mihomo)" ] && startfirewall;main $num;;
				2)
					if [ "$dns_ipv6" = "开" -a "$(cat $CLASHDIR/config.yaml 2> /dev/null | grep '^ .*ipv6:'| awk '{print $2}')" = "true" ];then
						[ "$dnsipv6_hijack" = "开" ] && dnsipv6_hijack=关 || dnsipv6_hijack=开
						[ "$(pidof mihomo)" ] && startfirewall
					else
						echo -e "\n$RED当前无法修改 ${SKYBLUE}DNS IPv6流量劫持 $RED选项！$RESET\n" && sleep 1
					fi;main $num;;
				0)
					main;;
			esac;;
		7)
			[ ! "$confignum" ] && {
				echo "========================================================="
				echo "请输入你的选项："
				echo "---------------------------------------------------------"
				[ "$common_ports" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
				echo -e "1. $GREEN开启$RESET/$RED关闭 $SKYBLUE仅常用端口代理\t\t$YELLOW当前状态：$states$RESET"
				echo -e "2. $YELLOW设     置 $SKYBLUE常用端口\t\t\t$YELLOW当前端口：$BLUE$multiports$RESET"
				echo "---------------------------------------------------------"
				echo "0. 返回上一页"
				echo && read -p "请输入对应选项的数字 > " confignum
			}
			case "$confignum" in
				1)
					[ "$common_ports" = "开" ] && common_ports=关 || common_ports=开
					[ "$(pidof mihomo)" ] && startfirewall;main $num;;
				2)
					echo &&read -p "请输入常用端口（隔开的端口请用逗号‘,’隔开，连续的端口请用短破折号‘-’连上）：" multiports_temp
					[ "$multiports_temp" ] && if [ "$multiports_temp" = "0" ];then
						main $num
					elif [ "$(echo $multiports_temp | sed 's/[0-9,-]//g')" -o "$(echo $multiports_temp | grep ^-)" ];then
						echo -e "\n$YELLOW请输入正确格式的端口！$RESET" && sleep 1 && main $num
					else
						for multiport in $(echo $multiports_temp | sed 's/[,-]/ /g');do [ $multiport -le 65535 ] && unpassed="" || { unpassed="true";break; };done
						if [ "$unpassed" ];then
							echo -e "\n$YELLOW请输入正确的端口！$RESET" && sleep 1 && main $num
						else
							multiports=$multiports_temp
							[ "$common_ports" = "开" ] && [ "$(pidof mihomo)" ] && startfirewall;main $num
						fi
					fi;;
				0)
					main;;
			esac;;
		8)
			echo "========================================================="
			echo "请输入你的选项："
			echo "---------------------------------------------------------"
			[ "$cnip_skip" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
			echo -e "1. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}CNIPv4绕过内核\t\t$YELLOW当前状态：$states$RESET"
			[ "$cnipv6_skip" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
			echo -e "2. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}CNIPv6绕过内核\t\t$YELLOW当前状态：$states$RESET"
			echo "---------------------------------------------------------"
			echo "0. 返回上一页"
			echo && read -p "请输入对应选项的数字 > " confignum
			case "$confignum" in
				1)
					[ "$cnip_skip" = "开" ] && cnip_skip=关 || cnip_skip=开
					[ "$(pidof mihomo)" ] && startfirewall;main $num;;
				2)
					[ "$cnip_skip" = "开" ] || return;
					[ "$cnipv6_skip" = "开" ] && cnipv6_skip=关 || cnipv6_skip=开
					[ "$(pidof mihomo)" ] && startfirewall;main $num;;
				0)
					main;;
			esac;;
		9)
			if [ "$(ip route | grep docker | awk '{print $1}' | head -1)" ];then
				[ "$Docker_Proxy" = "开" ] && Docker_Proxy=关 || Docker_Proxy=开
				[ "$(pidof mihomo)" ] && startfirewall
			else
				echo -e "\n$RED没有检测到 ${BLUE}Docker $RED正在运行！$RESET\n" && sleep 1
			fi;main;;
		10)
			showfirewall;;
		11)
			[ ! "$confignum" ] && {
				echo "========================================================="
				echo "请输入你的选项："
				echo "---------------------------------------------------------"
				[ "$subconverter" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
				echo -e "1. $GREEN开启$RESET/$RED关闭 $SKYBLUE订阅配置转换\t\t$YELLOW当前状态：$states$RESET"
				[ "$subconverter" = "开" ] && {
					[ "$udp_support" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
					echo -e "2. $GREEN开启$RESET/$RED关闭 $SKYBLUE节点UDP代理支持\t\t$YELLOW当前状态：$states$RESET"
					[ "$tls13" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
					echo -e "3. $GREEN开启$RESET/$RED关闭 $SKYBLUE节点TLS 1.3功能\t\t$YELLOW当前状态：$states$RESET"
					[ "$skip_cert_verify" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
					echo -e "4. $GREEN开启$RESET/$RED关闭 $SKYBLUE跳过节点证书验证\t\t$YELLOW当前状态：$states$RESET"
					echo -e "5. $YELLOW过     滤 $SKYBLUE节点\t\t\t$YELLOW当前过滤：$BLUE$exclude_name$RESET"
					echo -e "6. $YELLOW过     滤 $SKYBLUE节点类型\t\t\t$YELLOW当前过滤：$BLUE$exclude_type$RESET"
					[ "$(grep $sub_url$ $CLASHDIR/convert_server.ini)" ] && states="$BLUE$(grep $sub_url$ $CLASHDIR/convert_server.ini | sed 's/ http.*//')" || states="$SKYBLUE$sub_url"
					echo -e "7. $YELLOW切     换 $SKYBLUE订阅配置转换服务器\t\t$YELLOW正在使用：$states$RESET"
					[ "$config_url" ] && [ "$(grep $config_url$ $CLASHDIR/config_url.ini)" ] && states="$BLUE$(grep $config_url$ $CLASHDIR/config_url.ini | sed 's/ http.*//')" || states="$SKYBLUE$config_url"
					echo -e "8. $YELLOW切     换 $SKYBLUE订阅配置转换规则\t\t$YELLOW正在使用：$states$RESET"
				}
				echo -e "9. $YELLOW更     换 $SKYBLUE订阅链接地址\t\t$YELLOW正在使用：$SKYBLUE$sublink$RESET"
				[ "$subconverter" = "开" ] && echo -e "10.$YELLOW设     置 $SKYBLUE本地后端转换程序路径\t$YELLOW当前路径: $SKYBLUE$subconverter_path$RESET"
				echo "11.立即更新订阅配置"
				echo "---------------------------------------------------------"
				echo "0. 返回上一页"
				echo && read -p "请输入对应选项的数字 > " confignum
			}
			case "$confignum" in
				1)
					[ "$subconverter" = "开" ] && subconverter=关 || subconverter=开;main $num;;
				2)
					[ "$subconverter" = "开" ] || return;[ "$udp_support" = "开" ] && udp_support=关 || udp_support=开;main $num;;
				3)
					[ "$subconverter" = "开" ] || return;[ "$tls13" = "开" ] && tls13=关 || tls13=开;main $num;;
				4)
					[ "$subconverter" = "开" ] || return;[ "$skip_cert_verify" = "开" ] && skip_cert_verify=关 || skip_cert_verify=开;main $num;;
				5)
					[ "$subconverter" = "开" ] || return;
					echo && read -p "请输入需要过滤的节点关键字（如有多个请用竖线‘|’隔开）：" exclude_name
					exclude_name=$(echo $exclude_name | awk '{print $1}') && main $num;;
				6)
					[ "$subconverter" = "开" ] || return;
					echo && read -p "请输入需要过滤的节点类型关键字（如有多个请用竖线‘|’隔开）：" exclude_type
					exclude_type=$(echo $exclude_type | awk '{print $1}' | sed 's/[^ -~]//g') && main $num;;
				7)
					[ "$subconverter" = "开" ] || return;
					echo "========================================================="
					echo "请输入你的选项："
					echo "---------------------------------------------------------" && suburlcount=1
					while read LINE;do [ "$LINE" ] && echo -e "$(printf "%-53s%s\n" "$suburlcount. $SKYBLUE$(echo $LINE | awk '{print $NF}')$RESET" "$BLUE$(echo $LINE | sed 's/ http.*//')")$RESET" && let suburlcount++;done < $CLASHDIR/convert_server.ini
					[ "$(grep $sub_url$ $CLASHDIR/convert_server.ini)" ] && states="$BLUE$(grep $sub_url$ $CLASHDIR/convert_server.ini | sed 's/ http.*//')" || states="$SKYBLUE$sub_url"
					[ $suburlcount -gt 9 ] && blank="" || blank=" ";echo -e "$RESET$suburlcount.$blank自定义输入订阅配置转换服务器地址"
					echo "---------------------------------------------------------"
					echo -e "0. 返回上一页\t\t\t\t$YELLOW正在使用：$states$RESET"
					echo && read -p "请输入对应选项的数字 > " suburlnum
					case "$suburlnum" in
						$suburlcount)
							echo && read -p "请输入订阅配置转换服务器地址：" subserver_temp
							if [ "$(echo $subserver_temp | awk '{print $1}' | grep -E '^http://.*\.[^$]|^https://.*\.[^$]')" ];then
								sub_url=$(echo $subserver_temp | awk '{print $1}' | sed 's/[^ -~]//g') && main $num $confignum
							elif [ "$subserver_temp" ];then
								echo -e "\n$YELLOW请输入正确格式以http开头的订阅配置转换服务器地址！$RESET\n" && sleep 1 && main $num $confignum
							fi;;
						0)
							main $num;;
					esac
					[ "$suburlnum" -a ! "$(echo $suburlnum | sed 's/[0-9]//g')" ] && [ ! "$suburlnum" = 0 -a "$suburlnum" -lt "$suburlcount" ] && sub_url="$(sed -n "${suburlnum}p" $CLASHDIR/convert_server.ini | grep -o http.*)" && main $num $confignum;;
				8)
					[ "$subconverter" = "开" ] || return;
					echo "========================================================="
					echo "请输入你的选项："
					echo "---------------------------------------------------------" && configurlcount=1
					while read LINE;do [ "$LINE" ] && echo -e "$RESET$configurlcount. $BLUE$LINE" | sed 's/ http.*//' && let configurlcount++;done < $CLASHDIR/config_url.ini
					[ "$config_url" ] && [ "$(grep $config_url$ $CLASHDIR/config_url.ini)" ] && states="$BLUE$(grep $config_url$ $CLASHDIR/config_url.ini | sed 's/ http.*//')" || states="$SKYBLUE$config_url"
					[ $configurlcount -gt 9 ] && blank="" || blank=" ";echo -e "$RESET$configurlcount.$blank自定义输入订阅配置转换规则地址" && let configurlcount++
					[ $configurlcount -gt 9 ] && blank="" || blank=" ";echo -e "$RESET$configurlcount.$blank$SKYBLUE使用订阅配置转换服务器默认规则$RESET"
					echo "---------------------------------------------------------"
					echo -e "0. 返回上一页\t\t\t\t$YELLOW正在使用：$states$RESET"
					echo && read -p "请输入对应选项的数字 > " configurlnum
					case "$configurlnum" in
						$((configurlcount-1)))
							echo && read -p "请输入订阅配置转换规则地址：" configserver_temp
							if [ "$(echo $configserver_temp | awk '{print $1}' | grep -E '^http://.*\.[^$]|^https://.*\.[^$]')" ];then
								config_url=$(echo $configserver_temp | awk '{print $1}' | sed 's/[^ -~]//g') && main $num $confignum
							elif [ "$configserver_temp" ];then
								echo -e "\n$YELLOW请输入正确格式以http开头的订阅配置转换规则地址！$RESET\n" && sleep 1 && main $num $confignum
							fi;;
						$configurlcount)
							config_url="" && main $num $confignum;;
						0)
							main $num;;
					esac
					[ "$configurlnum" -a ! "$(echo $configurlnum | sed 's/[0-9]//g')" ] && [ ! "$configurlnum" = 0 -a "$configurlnum" -lt "$configurlcount" ] && config_url="$(sed -n "${configurlnum}p" $CLASHDIR/config_url.ini | grep -o http.*)" && main $num $confignum;;
				9)
					echo && read -p "请输入订阅链接地址（如有多个请用竖线‘|’隔开）：" sublink_temp
					if [ "$(echo $sublink_temp | awk '{print $1}' | grep -E '^http://.*\.[^$]|^https://.*\.[^$]')" ];then
						sublink=$(echo $sublink_temp | awk '{print $1}' | sed 's/[^ -~]//g') && main $num
					else
						echo -e "\n$YELLOW请输入正确格式以http开头的订阅链接地址！$RESET\n" && sleep 1 && main $num
					fi;;
				10)
					[ "$subconverter" = "开" ] || return;
					echo && read -p "请输入本地后端转换程序的绝对路径：" subconverter_path_temp
					if [ "$(echo $subconverter_path_temp | awk '{print $1}' | grep ^/.*)" -a "${subconverter_path_temp:1}" ];then
						$subconverter_path_temp 2>&1 | grep Startup > /tmp/subconverter_path_test & sleep 1
						while [ "$(ps | grep -v grep | grep "$subconverter_path_temp" 2> /dev/null | head -1 | awk '{print $1}')" ];do killpid $(ps | grep -v grep | grep "$subconverter_path_temp" | head -1 | awk '{print $1}');done
						[ "$(cat /tmp/subconverter_path_test 2> /dev/null)" ] && subconverter_path=$(echo $subconverter_path_temp | awk '{print $1}') && rm -f /tmp/subconverter_path_test && main $num || { echo -e "\n$RED请输入本地后端转换程序 ${BLUE}subconverter $YELLOW的绝对路径！$RESET" && sleep 1 && main $num; }
					elif [ "$subconverter_path_temp" = 0 ];then
						main $num
					elif [ "$subconverter_path_temp" ];then
						echo -e "\n$YELLOW请输入正确格式以斜杠‘/’开头的程序所在绝对路径！$RESET\n" && sleep 1 && main $num
					else
						subconverter_path="" && main $num
					fi;;
				11)
					[ "$(pidof mihomo)" ] && {
						echo "========================================================="
						echo -e "${BLUE}Clash-mihomo $YELLOW正在运行中！更新前需要先停止运行 ${BLUE}Clash-mihomo $YELLOW！$RESET"
						echo "---------------------------------------------------------"
						echo "1. 确认停止运行并更新"
						echo "---------------------------------------------------------"
						echo "0. 返回上一页"
						echo && read -p "请输入对应选项的数字 > " mihomonum && [ "$mihomonum" = "1" ] || { [ "$mihomonum" = "0" ] && main $num || exit; }
					}
					mv -f $CLASHDIR/config_original.yaml $CLASHDIR/config_original.yaml.backup 2> /dev/null;stop && start;;
				0)
					main;;
			esac;;
		12)
			[ "$(pidof mihomo)" ] && {
				echo "========================================================="
				echo -e "${BLUE}Clash-mihomo $YELLOW正在运行中！更新前需要先停止运行 ${BLUE}Clash-mihomo $YELLOW！$RESET"
				echo "---------------------------------------------------------"
				echo "1. 确认停止运行并更新"
				echo "---------------------------------------------------------"
				echo "0. 返回上一页"
				echo && read -p "请输入对应选项的数字 > " mihomonum && [ "$mihomonum" = "1" ] || { [ "$mihomonum" = "0" ] && main $num || exit; }
			}
			update;;
		13)
			if [ "$(grep "$0 start$" /etc/rc.d/S99Clash_mihomo 2> /dev/null)" ];then
				rm -f /etc/init.d/Clash_mihomo /etc/rc.d/S99Clash_mihomo && main
			else
				echo -e "#!/bin/sh /etc/rc.common\n\nSTART=99\n\nstart() {\n\t$0 start\n}" > /etc/init.d/Clash_mihomo && chmod +x /etc/init.d/Clash_mihomo && /etc/init.d/Clash_mihomo enable && main
			fi;;
		88)
			echo "========================================================="
			echo -e "$YELLOW请确认是否卸载：（$BLUE$CLASHDIR$RED文件夹及里面所有文件将会被删除！！！$YELLOW）$RESET"
			echo "---------------------------------------------------------"
			echo "1. 确认卸载"
			echo "---------------------------------------------------------"
			echo "0. 返回上一页"
			echo && read -p "请输入对应选项的数字 > " deletenum
			case "$deletenum" in
				1)
					stop && sed -i '/clash=/d' /etc/profile && sed -i '/./,/^$/!d' /etc/profile && sed -i '/Clash/d' /etc/passwd && rm -rf $CLASHDIR /etc/init.d/Clash_mihomo /etc/rc.d/S99Clash_mihomo && echo -e "\n${BLUE}Clash-mihomo $RED已一键卸载！请重进SSH清除clash命令变量环境！再会！$RESET";;
				0)
					main;;
			esac;;
	esac
}
case "$1" in
	1|start)start;;
	2|stop)stop;;
	10|showfirewall)showfirewall;;
	11|config_update)mv -f $CLASHDIR/config_original.yaml $CLASHDIR/config_original.yaml.backup 2> /dev/null;stop && start;;
	12|update)update;;
	crontab)update crontab;;
	stopfirewall)stopfirewall;;
	startfirewall)startfirewall;;
	*)main;;
esac
