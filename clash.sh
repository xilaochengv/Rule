CLASHDIR=$(dirname $0) && [ -s $CLASHDIR/config.ini ] && . $CLASHDIR/config.ini
RED='\e[0;31m';GREEN='\e[1;32m';YELLOW='\e[1;33m';BLUE='\e[1;34m';PINK='\e[1;35m';SKYBLUE='\e[1;36m';RESET='\e[0m'
sed -i '/clash=/d' /etc/profile && echo -e "\nexport CLASHDIR=$(dirname $0);alias clash=\"$0\"" >> /etc/profile && sed -i '/./,/^$/!d' /etc/profile
[ ! "$(uci -q get firewall.firewalluser.path)" ] && echo -e "config inculde 'firewalluser'\n\toption path '/etc/firewall.user'\n\toption reload '1'" >> /etc/config/firewall && sed -i '/./,/^$/!d' /etc/config/firewall
sed -i '/clash/d' /etc/firewall.user 2> /dev/null;[ ! "$(grep "$0 start$" /etc/firewall.user 2> /dev/null)" ] && echo -e "[ \"\$(pidof mihomo)\" ] && $0 startfirewall" >> /etc/firewall.user
route=$(ip route | grep br-lan | awk {'print $1'})
routes="127.0.0.0/8 $route"
routev6=$(ip -6 route | grep br-lan | awk '{print $1}')
routesv6="::1 $routev6"
localip=$(ip route | grep br-lan | awk {'print $9'})
wanipv4=$(ip -o addr | grep pppoe-wan | grep 'inet ' | awk '{print $4}')
wanipv6=$(ip -o addr | grep pppoe-wan | grep inet6.*global | sed -e 's/.*inet6 //' -e 's#/.*##')
[ ! "$sublink" ] && sublink='订阅链接|多个订阅地址请用|竖线分割'
[ ! "$exclude_name" ] && exclude_name='节点名称过滤|多个关键字请用|竖线分割'
[ ! "$exclude_type" ] && exclude_type='节点类型过滤|多个关键字请用|竖线分割'
[ ! "$udp_support" ] && udp_support=关
[ ! "$sub_url" ] && sub_url=https://sub.id9.cc
[ ! "$(echo $config_url | grep ^http)" ] && config_url=https://raw.githubusercontent.com/xilaochengv/Rule/main/rule.ini
[ ! "$geoip_url" ] && geoip_url=https://github.com/xilaochengv/Rule/releases/download/Latest/geoip.dat
[ ! "$geosite_url" ] && geosite_url=https://github.com/xilaochengv/Rule/releases/download/Latest/geosite.dat
[ ! "$redir_port" ] && redir_port=25274
[ ! "$authusername" ] && authusername=username
[ ! "$authpassword" ] && authpassword=password
[ ! "$dashboard_port" ] && dashboard_port=6789
[ ! "$core_ipv6" ] && core_ipv6=开
[ ! "$dns_ipv6" ] && dns_ipv6=开
[ ! "$dns_hijack" ] && dns_hijack=关
[ ! "$dnsipv6_hijack" -o "$dns_ipv6" != "开" -o "$(cat $CLASHDIR/config.yaml 2> /dev/null | grep '  ipv6:'| awk '{print $2}')" != "true" ] && dnsipv6_hijack=关
[ ! "$dns_port" ] && dns_port=1053
[ ! "$dns_default" ] && dns_default='223.6.6.6'
[ ! "$dns_fallback" ] && dns_fallback='tls://1.0.0.1, tls://8.8.4.4'
[ ! "$mac_filter" ] && mac_filter=关
[ ! "$mac_filter_mode" ] && mac_filter_mode=黑名单
[ ! "$cnip_route" ] && cnip_route=关
[ ! "$cnipv6_route" ] && cnipv6_route=关
[ ! "$common_ports" ] && common_ports=关
[ ! "$multiports" ] && multiports=53,80,123,143,194,443,465,587,853,993,995,5222,8080,8443
[ ! "$Docker_Proxy" -o ! "$(ip route | grep docker | awk '{print $1}' | head -1)" ] && Docker_Proxy=关
[ ! "$Clash_Local_Proxy" ] && Clash_Local_Proxy=关
[ -s $CLASHDIR/custom_rules.ini ] || echo -e "#说明文档：https://wiki.metacubex.one/config/rules\n#填写格式：\n#DOMAIN,baidu.com,DRIECT（不需要填前面的-符号）" > $CLASHDIR/custom_rules.ini
[ ! "$(grep ^http $CLASHDIR/mirror_server.ini 2> /dev/null)" ] && echo -e "https://gh.ddlc.top\nhttps://mirror.ghproxy.com\nhttps://hub.gitmirror.com" > $CLASHDIR/mirror_server.ini
[ ! "$(grep http $CLASHDIR/convert_server.ini 2> /dev/null)" ] && echo -e "品云提供 https://sub.id9.cc\n品云备用 https://v.id9.cc\n肥羊增强 https://url.v1.mk\n肥羊备用 https://sub.d1.mk\nnameless13提供 https://www.nameless13.com\nsubconverter作者提供 https://sub.xeton.dev\nsub-web作者提供 https://api.wcc.best\nsub作者 & lhie1提供 https://api.dler.io" > $CLASHDIR/convert_server.ini
[ ! "$(grep http $CLASHDIR/config_url.ini 2> /dev/null)" ] && echo -e "作者自用GEO精简规则 https://raw.githubusercontent.com/xilaochengv/Rule/main/rule.ini\n默认版规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini\n精简版规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini\n更多去广告规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_AdblockPlus.ini\n多国分组规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_MultiCountry.ini\n无自动测速规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoAuto.ini\n无广告拦截规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoReject.ini\n全分组规则 重度用户使用 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini" > $CLASHDIR/config_url.ini
Filesystem=$(dirname $0);while [ ! "$(df $Filesystem)" ];do Filesystem=$(echo ${Filesystem%/*});done;Filesystem=$(df $Filesystem | tail -1 | awk '{print $6}');Available=$(df $Filesystem | tail -1 | awk '{print $4}')
[ ! -f $CLASHDIR/mihomo -a $Available -lt 3000 ] && echo -e "$RED当前脚本存放位置 $BLUE$0 $RED的所在分区 $BLUE$Filesystem $RED空间不足！请更换本脚本存放位置！$RESET" && exit
start(){
	stop start && update missingfiles
	[ "$core_ipv6" = "开" ] && ipv6_core=true || ipv6_core=false
	[ "$dns_ipv6" = "开" ] && ipv6_dns=true || ipv6_dns=false
	cat > $CLASHDIR/config.yaml << EOF
redir-port: $redir_port
mixed-port: $(($redir_port+1))
allow-lan: true
authentication:
  - "$authusername:$authpassword"
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
$(sed -n '/^proxies/,/^rules/p' $CLASHDIR/config_original.yaml)
EOF
	sed -n '/^rules/,/*/p' $CLASHDIR/config_original.yaml | tail +2 > $CLASHDIR/rules.yaml && sed -i 's/GEOIP.*/&,no-resolve/' $CLASHDIR/rules.yaml
	spaces=$(sed -n 1p $CLASHDIR/rules.yaml | grep -oE '^ *- *')
	sed -n '/^[^#]/p' $CLASHDIR/custom_rules.ini | sed "s/.*/$spaces&\t#自定义规则/" >> $CLASHDIR/config.yaml
	cat $CLASHDIR/rules.yaml >> $CLASHDIR/config.yaml && rm -f $CLASHDIR/rules.yaml
	error="$($CLASHDIR/mihomo -d $CLASHDIR -t $CLASHDIR/config.yaml | grep error | awk -F = '{print $3"="$NF}')"
	[ "$error" ] && echo -e "\n${BLUE}Clash-mihomo $RED启动失败！\n$RESET\n$error\n" && exit
	sed -i '/Clash/d' /etc/passwd && echo "Clash:x:0:$redir_port:::" >> /etc/passwd
	modprobe tun 2> /dev/null
	start-stop-daemon -Sbc Clash:$redir_port -x $CLASHDIR/mihomo -- -d $CLASHDIR &
	while [ ! "$(ifconfig | grep utun)" ];do usleep 100000;done
	startfirewall && date +%s > $CLASHDIR/starttime
	curl -so /dev/null "http://127.0.0.1:$dashboard_port/group/节点选择/delay?url=https://www.google.com/generate_204&timeout=5000" &
	echo -e "while [ \"\$(pidof mihomo)\" ];do\n\tsleep 10\n\t[ \$(awk 'NR==3{print \$2}' /proc/meminfo) -lt 102400 ] && curl -so /dev/null \"http://127.0.0.1:$dashboard_port/debug/gc\" -X PUT\n\t[ ! \"\$(iptables -t mangle -nvL Clash)\" ] && $0 startfirewall\ndone" > /tmp/autooc.sh && chmod 755 /tmp/autooc.sh && /tmp/autooc.sh &
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
	echo "sublink='$sublink'" > $CLASHDIR/config.ini
	echo "exclude_name='$exclude_name'" >> $CLASHDIR/config.ini
	echo "exclude_type='$exclude_type'" >> $CLASHDIR/config.ini
	echo "udp_support=$udp_support" >> $CLASHDIR/config.ini
	echo "sub_url='$sub_url'" >> $CLASHDIR/config.ini
	echo "mirrorserver='$mirrorserver'" >> $CLASHDIR/config.ini
	echo "config_url='$config_url'" >> $CLASHDIR/config.ini
	echo "geoip_url='$geoip_url'" >> $CLASHDIR/config.ini
	echo "geosite_url='$geosite_url'" >> $CLASHDIR/config.ini
	echo -e "\n#修改以下配置前，必须先运行脚本并选择2停止Clash-mihomo！否则修改前的防火墙规则无法清理干净！" >> $CLASHDIR/config.ini
	echo "redir_port=$redir_port" >> $CLASHDIR/config.ini
	echo -e "\n#以下配置修改后，需要重启Clash-mihomo后才能生效" >> $CLASHDIR/config.ini
	echo "authusername='$authusername'" >> $CLASHDIR/config.ini
	echo "authpassword='$authpassword'" >> $CLASHDIR/config.ini
	echo "dashboard_port=$dashboard_port" >> $CLASHDIR/config.ini
	echo "core_ipv6=$core_ipv6" >> $CLASHDIR/config.ini
	echo "dns_ipv6=$dns_ipv6" >> $CLASHDIR/config.ini
	echo "dns_port=$dns_port" >> $CLASHDIR/config.ini
	echo "dns_default='$dns_default'" >> $CLASHDIR/config.ini
	echo "dns_fallback='$dns_fallback'" >> $CLASHDIR/config.ini
	echo -e "\n#以下配置只需要运行脚本并选择3-9即可修改" >> $CLASHDIR/config.ini
	echo "dns_hijack=$dns_hijack" >> $CLASHDIR/config.ini
	echo "dnsipv6_hijack=$dnsipv6_hijack" >> $CLASHDIR/config.ini
	echo "mac_filter=$mac_filter" >> $CLASHDIR/config.ini
	echo "mac_filter_mode=$mac_filter_mode" >> $CLASHDIR/config.ini
	echo "cnip_route=$cnip_route" >> $CLASHDIR/config.ini
	echo "cnipv6_route=$cnipv6_route" >> $CLASHDIR/config.ini
	echo "common_ports=$common_ports" >> $CLASHDIR/config.ini
	echo "Docker_Proxy=$Docker_Proxy" >> $CLASHDIR/config.ini
	echo "Clash_Local_Proxy=$Clash_Local_Proxy" >> $CLASHDIR/config.ini
	echo -e "\n#以下配置修改后，需要运行脚本并选择3-9随意一项才可马上生效" >> $CLASHDIR/config.ini
	multiports=$(echo $multiports | sed 's/[^0-9\-]/,/g')
	echo "multiports=$multiports" >> $CLASHDIR/config.ini
	echo "dns_server_ip_filter='$dns_server_ip_filter'" >> $CLASHDIR/config.ini
	[ ! "$(echo $sublink | grep //)" ] && echo -e "$RED请先在 $SKYBLUE$CLASHDIR/config.ini $RED文件中填写好订阅链接地址！$YELLOW（现在退出并重进SSH即可直接使用clash命令）$RESET" && exit
	return 0
}
githubdownload(){
	rm -f $1 && failedcount=0 && http_code=0 && dlurl=$3 && [ "$(echo $dlurl | grep -vE '/http|=http' | grep -E 'github.com/|githubusercontent.com/')" ] && dlurl="$(echo $dlurl | sed "s#.*#$(echo $mirrorserver | sed 's/[^/]$/&\//')&#")"
	echo -e "\n$YELLOW下载$2 $SKYBLUE$dlurl $YELLOW······$RESET \c"
	http_code=$(curl -m 10 -sLko $1 "$dlurl" -w "%{http_code}")
	while [ $? != 0 -a $failedcount -lt 3 -o $http_code != 200 -a $failedcount -lt 3 ];do
		rm -f $1 && echo -e "$RED下载失败！即将尝试重新下载！已重试次数：$failedcount$RESET" && sleep 1 && let failedcount++
		echo -e "\n$YELLOW下载$2 $SKYBLUE$dlurl $YELLOW······$RESET \c" && http_code=$(curl -m 10 -sLko $1 "$dlurl" -w "%{http_code}")
	done
	[ $? != 0 -o $http_code != 200 ] && rm -f $1 && return 1
	echo -e "$GREEN下载成功！$RESET"
}
update(){
	[ ! "$1" -o "$1" = "crontab" ] && while [ -f /tmp/iptv_scaning ];do sleep 1;done && stop && rm -rf $CLASHDIR/ui $CLASHDIR/cn_ip.txt $CLASHDIR/cn_ipv6.txt $CLASHDIR/config.yaml $CLASHDIR/GeoIP.dat $CLASHDIR/GeoSite.dat && mv -f $CLASHDIR/config_original.yaml $CLASHDIR/config_original.yaml.backup 2> /dev/null
	[ ! "$1" ] && rm -f $CLASHDIR/mihomo
	[ ! -d $CLASHDIR/ui ] && {
		githubdownload "/tmp/dashboard" "Meta基础面板" "https://raw.githubusercontent.com/juewuy/ShellCrash/dev/bin/dashboard/meta_db.tar.gz"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
		mkdir -m 755 $CLASHDIR/ui && tar -zxf /tmp/dashboard -C $CLASHDIR/ui && rm -f /tmp/dashboard
		sed -i "s/9090/$dashboard_port/g;s/127.0.0.1/$localip/g" $CLASHDIR/ui/assets/index.628acf3b.js
	}
	[ ! -f $CLASHDIR/mihomo ] && {
		while [ ! "$latestversion" ];do latestversion=$(curl --connect-timeout 3 -sk "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" | grep tag_name | cut -f4 -d '"');done
		githubdownload "/tmp/mihomo.gz" "Clash主程序文件" "https://github.com/MetaCubeX/mihomo/releases/download/$latestversion/mihomo-linux-arm64-$latestversion.gz"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
		rm -f $CLASHDIR/mihomo /tmp/mihomo && gzip -d /tmp/mihomo.gz && chmod 755 /tmp/mihomo && mv -f /tmp/mihomo $CLASHDIR/mihomo 2> /dev/null || ln -sf /tmp/mihomo $CLASHDIR/mihomo
	}
	[ ! -f $CLASHDIR/config_original.yaml ] && {
		exclude_type_temp=$(echo $exclude_type | sed 's/|/\\\|/g')
		subs=1 && for url in $(echo $sublink | sed 's/|/ /g');do
			[ "$udp_support" = "开" ] && sub_udp=true || sub_udp=false
			url=$(echo $url | sed 's/;/\%3B/g;s|/|\%2F|g;s/?/\%3F/g;s/:/\%3A/g;s/@/\%40/g;s/=/\%3D/g;s/&/\%26/g')
			githubdownload "$CLASHDIR/config_original_temp_$subs.yaml" "配置文件" "$sub_url/sub?target=clash&new_name=true&scv=true&udp=$sub_udp&exclude_name=$exclude_name&url=$url&config=$config_url"
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
		done && exclude_type_name=$(grep $exclude_type_temp $CLASHDIR/proxies.yaml | awk -F , '{print $1}' | sed 's/.*: //;s/ /*/g') && [ "$exclude_type_name" ] && sed -i "/type: $exclude_type_temp/d" $CLASHDIR/proxies.yaml
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
		done && exclude_type_name=$(echo $exclude_type_name | sed 's/ /\\\|/g;s/*/ /g') && [ "$exclude_type_name" ] && sed -i "/$exclude_type_name/d" $CLASHDIR/proxy-groups.yaml
		echo "proxies:" > $CLASHDIR/config_original.yaml && cat $CLASHDIR/proxies.yaml >> $CLASHDIR/config_original.yaml
		echo "proxy-groups:" >> $CLASHDIR/config_original.yaml && cat $CLASHDIR/proxy-groups.yaml $CLASHDIR/rules.yaml >> $CLASHDIR/config_original.yaml
		rm -f $CLASHDIR/config_original_temp_*.yaml $CLASHDIR/proxy-groups_temp_*.yaml $CLASHDIR/proxies.yaml $CLASHDIR/proxy-groups.yaml $CLASHDIR/rules.yaml
	}
	[ ! -f $CLASHDIR/cn_ip.txt -a "$cnip_route" = "开" ] && {
		githubdownload "$CLASHDIR/cn_ip.txt" "CN-IP数据库文件" "https://github.com/xilaochengv/Rule/releases/download/Latest/cn_ip.txt"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ ! -f $CLASHDIR/cn_ipv6.txt -a "$core_ipv6" = "开" -a "$cnipv6_route" = "开" ] && {
		githubdownload "$CLASHDIR/cn_ipv6.txt" "CN-IPV6数据库文件" "https://github.com/xilaochengv/Rule/releases/download/Latest/cn_ipv6.txt"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ "$(grep -i geoip $CLASHDIR/config_original.yaml)" ] && [ ! -f $CLASHDIR/GeoIP.dat ] && {
		githubdownload "$CLASHDIR/GeoIP.dat" "GeoIP数据库文件" "$geoip_url"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ "$(grep -i geosite $CLASHDIR/config_original.yaml)" ] && [ ! -f $CLASHDIR/GeoSite.dat ] && {
		githubdownload "$CLASHDIR/GeoSite.dat" "GeoSite数据库文件" "$geosite_url"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ ! "$1" -o "$1" = "restore" -o "$1" = "crontab" ] && start
	return 0
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
			[ "$(echo $port | grep -)" ] && port=$(echo $port | sed 's/-/:/') && let amount++
			[ $amount == 15 ] && {
				ports=$(echo $ports | sed 's/^,//')
				iptables -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
				iptables -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
				[ "$core_ipv6" = "开" ] && {
					ip6tables -t mangle -A PREROUTING -p udp -m multiport --dports $ports -m comment --comment "udp常用端口流量进入Clash规则链" -j Clash
					ip6tables -t nat -A PREROUTING -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口流量进入Clash规则链" -j Clash
				}
				amount=1 && ports=""
			}
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
	[ "$wanipv4" ] && {
		iptables -t mangle -A Clash -d $wanipv4 -p udp -m comment --comment "udp流量目标地址为本地WAN口IPv4地址，直接绕过Clash内核" -j RETURN
		iptables -t nat -A Clash -d $wanipv4 -p tcp -m comment --comment "tcp流量目标地址为本地WAN口IPv4地址，直接绕过Clash内核" -j RETURN
		[ "$wanipv6" -a "$core_ipv6" = "开" ] && {
			ip6tables -t mangle -A Clash -d $wanipv6 -p udp -m comment --comment "udp流量目标地址为本地WAN口IPv6地址，直接绕过Clash内核" -j RETURN
			ip6tables -t nat -A Clash -d $wanipv6 -p tcp -m comment --comment "tcp流量目标地址为本地WAN口IPv6地址，直接绕过Clash内核" -j RETURN
		}
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
		if [ "$(grep -v '^ *#' $CLASHDIR/maclist.ini 2> /dev/null)" ];then
			while read LINE;do
				ip=$(echo $LINE | grep -v '^ *#' | awk '{print $1}' | grep '\.')
				mac=$(echo $LINE | grep -v '^ *#' | awk '{print $1}' | grep ':')
				device=$(echo $LINE | grep -v '^ *#' | awk '{for(i=2;i<=NF;i++){printf"%s ",$i};print out}' | sed 's/ $//');[ ! "$device" ] && device=设备名称未填写
				[ "$ip" ] && [ "$ip" != "$localip" ] && {
					if [ "$mac_filter_mode" = "白名单" ];then
						iptables -t mangle -A Clash -s $ip -p udp -m comment --comment "udp流量进入Clash内核（$device）" -j MARK --set-mark $redir_port
						iptables -t nat -A Clash -s $ip -p tcp -m comment --comment "tcp流量进入Clash内核（$device）" -j REDIRECT --to-port $redir_port
						[ "$core_ipv6" = "开" ] && echo -e "$BLUE$ip $RED加入ipv6防火墙白名单失败！（不支持使用ipv4地址进行添加，如有需要请将设备名单修改为mac地址）$RESET"
					else
						iptables -t mangle -A Clash -s $ip -p udp -m comment --comment "udp流量禁止进入Clash内核（$device）" -j RETURN
						iptables -t nat -A Clash -s $ip -p tcp -m comment --comment "tcp流量禁止进入Clash内核（$device）" -j RETURN
						[ "$core_ipv6" = "开" ] && echo -e "$BLUE$ip $RED加入ipv6防火墙黑名单失败！（不支持使用ipv4地址进行添加，如有需要请将设备名单修改为mac地址）$RESET"
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
			done < $CLASHDIR/maclist.ini
		else
			[ -s $CLASHDIR/maclist.ini ] || echo -e "#黑白名单列表（可填IP或MAC地址）\n#192.168.1.100\t我的电脑\n#aa:bb:cc:dd:ee:ff\t设备名称（可填可不填）" > $CLASHDIR/maclist.ini
			echo -e "\n$RED常用设备名单无内容！请配置 $BLUE$CLASHDIR/maclist.ini$RED 文件！$RESET" && sleep 2
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
	[ "$Docker_Proxy" = "开" ] && [ "$(ip route | grep docker | awk '{print $1}' | head -1)" ] && {
		route_docker=$(ip route | grep docker | awk '{print $1}' | head -1)
		route_dockerv6=$(ip -6 route | grep docker | awk '{print $1}')
		iptables -t mangle -A Clash -s $route_docker -p udp -m comment --comment "udp流量进入Clash内核（$route_docker网段）" -j MARK --set-mark $redir_port
		iptables -t nat -A Clash -s $route_docker -p tcp -m comment --comment "tcp流量进入Clash内核（$route_docker网段）" -j REDIRECT --to-port $redir_port
		[ "$core_ipv6" = "开" ] && {
			for route_docker6 in $route_dockerv6;do
				ip6tables -t mangle -A Clash -s $route_dockerv6 -p udp -m comment --comment "udp流量进入Clash内核（$route_dockerv6网段）" -j MARK --set-mark $redir_port
				ip6tables -t nat -A Clash -s $route_dockerv6 -p tcp -m comment --comment "tcp流量进入Clash内核（$route_dockerv6网段）" -j REDIRECT --to-port $redir_port
			done
		}
	}
	[ "$dns_hijack" = "开" ] && {
		iptables -t nat -N Clash_DNS
		iptables -t nat -I PREROUTING -p udp --dport 53 -m comment --comment "DNS流量进入Clash_DNS规则链" -j Clash_DNS
		iptables -t nat -I OUTPUT -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash_DNS规则链" -j Clash_DNS
		iptables -t nat -A Clash_DNS -d $localip -p udp --dport 53 -m comment --comment "DNS流量进入Clash内核" -j REDIRECT --to-ports $dns_port
		iptables -t nat -A Clash_DNS -s 127.0.0.0/8 -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash内核" -j REDIRECT --to-ports $dns_port
	}
	[ "$dnsipv6_hijack" = "开" ] && {
		ip6tables -t nat -N Clash_DNS
		ip6tables -t nat -I PREROUTING -p udp --dport 53 -m comment --comment "DNS流量进入Clash_DNS规则链" -j Clash_DNS
		ip6tables -t nat -I OUTPUT -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash_DNS规则链" -j Clash_DNS
		for localipv6dns in $(route -A inet6 | grep '^fe80.*[0-9a-f]/128.*Un' | awk '{print $1}');do
			ip6tables -t nat -A Clash_DNS -d $localipv6dns -p udp --dport 53 -m comment --comment "DNS流量进入Clash内核" -j REDIRECT --to-ports $dns_port
		done
		ip6tables -t nat -A Clash_DNS -s ::1 -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash内核" -j REDIRECT --to-ports $dns_port
	}
	[ "$wanipv4" -a "$Clash_Local_Proxy" = "开" ] && {
		iptables -t nat -N Clash_Local_Proxy
		[ "$core_ipv6" = "开" ] && ip6tables -t nat -N Clash_Local_Proxy
		if [ "$common_ports" = "开" ];then
			ports="" && amount=0 && for port in $(echo $multiports | awk -F , '{for(i=1;i<=NF;i++){print $i};}');do
				[ "$(echo $port | grep -)" ] && port=$(echo $port | sed 's/-/:/') && let amount++
				[ $amount == 15 ] && {
					ports=$(echo $ports | sed 's/^,//')
					iptables -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					[ "$core_ipv6" = "开" ] && ip6tables -t nat -A OUTPUT -p tcp -m multiport --dports $ports -m comment --comment "tcp常用端口本机流量进入Clash_Local_Proxy规则链" -j Clash_Local_Proxy
					amount=1 && ports=""
				}
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
		[ "$wanipv6" -a "$core_ipv6" = "开" ] && ip6tables -t nat -A Clash_Local_Proxy -s $wanipv6 -p tcp -m comment --comment "tcp本机流量进入Clash内核" -j REDIRECT --to-port $redir_port
	}
	return 0
}
stopfirewall(){
	while [ "$(ip6tables -t nat -S OUTPUT | grep 常用端口)" ];do
		eval ip6tables -t nat $(ip6tables -t nat -S OUTPUT | grep 常用端口 | sed 's/-A/-D/' | head -1) 2> /dev/null
	done
	ip6tables -t nat -D PREROUTING -p udp --dport 53 -m comment --comment "DNS流量进入Clash_DNS规则链" -j Clash_DNS 2> /dev/null
	ip6tables -t nat -D OUTPUT -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash_DNS规则链" -j Clash_DNS 2> /dev/null
	ip6tables -t nat -F Clash_DNS 2> /dev/null
	ip6tables -t nat -X Clash_DNS 2> /dev/null
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
	iptables -t nat -D PREROUTING -p udp --dport 53 -m comment --comment "DNS流量进入Clash_DNS规则链" -j Clash_DNS 2> /dev/null
	iptables -t nat -D OUTPUT -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash_DNS规则链" -j Clash_DNS 2> /dev/null
	iptables -t nat -F Clash_DNS 2> /dev/null
	iptables -t nat -X Clash_DNS 2> /dev/null
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
		[ "$(iptables -t nat -S OUTPUT | grep Clash)" ] && echo && iptables -t nat -nvL OUTPUT && echo && {
			iptables -t nat -nvL Clash_DNS 2> /dev/null && echo
			iptables -t nat -nvL Clash_Local_Proxy 2> /dev/null
		}
	}
	echo -e "\n-------------------------------------------FILTER-------------------------------------------" && {
		[ "$(iptables -S FORWARD | grep utun)" ] && iptables -nvL FORWARD
	}
	[ "$routev6" ] && echo -e "\n----------------------------------------IPv6  MANGLE----------------------------------------" && {
		[ "$(ip6tables -t mangle -S PREROUTING | grep Clash)" ] && ip6tables -t mangle -nvL PREROUTING && echo && ip6tables -t mangle -nvL Clash
	}
	[ "$routev6" ] && echo -e "\n-----------------------------------------IPv6  NAT------------------------------------------" && {
		[ "$(ip6tables -t nat -S PREROUTING | grep Clash)" ] && ip6tables -t nat -nvL PREROUTING && echo && ip6tables -t nat -nvL Clash 2> /dev/null
		[ "$(ip6tables -t nat -S OUTPUT | grep Clash)" ] && echo && ip6tables -t nat -nvL OUTPUT && echo && {
			ip6tables -t nat -nvL Clash_DNS 2> /dev/null && echo
			ip6tables -t nat -nvL Clash_Local_Proxy 2> /dev/null
		}
	}
	[ "$routev6" ] && echo -e "\n----------------------------------------IPv6  FILTER----------------------------------------" && {
		[ "$(ip6tables -S FORWARD | grep utun)" ] && ip6tables -nvL FORWARD
	}
	return 0
}
#修复小米AX9000开启QOS时若Clash-mihomo正在运行而导致某些特定udp端口流量（如80 8080等）无法通过问题
[ "$(uci get /usr/share/xiaoqiang/xiaoqiang_version.version.HARDWARE 2> /dev/null)" = "RA70" ] && \
sed -i "s@\[ -d /sys/module/shortcut_fe_cm ] |@\[ -d /sys/module/shortcut_fe_cm -o -n \"\$(pidof mihomo)\" ] |@" /etc/init.d/shortcut-fe
main(){
	cniproutenum="" && dnshijacknum="" && confignum=$2 && suburlcount=1 && suburlnum="" && configurlcount=1 && configurlnum="" && configserver_temp="" && deletenum="" && mirrorurlcount=1 && mirrorurlnum="" && mirrorserver_temp=""
	saveconfig && num="$1" && [ ! "$num" ] && echo && {
		echo "========================================================="
		echo "请输入你的选项："
		echo "---------------------------------------------------------"
		[ -s $CLASHDIR/starttime -a "$(pidof mihomo)" ] && states="$PINK$(awk BEGIN'{printf "%0.2f MB",'$(cat /proc/$(pidof mihomo)/status 2> /dev/null | grep -w VmRSS | awk '{print $2}')'/1024}')" || states="$RED已停止"
		echo -e "1.  $GREEN重新启动 ${BLUE}Clash-mihomo$RESET\t\t${YELLOW}运存占用：$states$RESET"
		if [ -s $CLASHDIR/starttime -a "$(pidof mihomo)" ];then
			TotalSeconeds=$(($(date +%s)-$(cat $CLASHDIR/starttime)))
			Days=$(awk BEGIN'{printf "%d",'$TotalSeconeds'/60/60/24}') && [ "$Days" -gt 0 ] && Days=$Days天 || Days=""
			Hours=$(awk BEGIN'{printf "%d\n",'$TotalSeconeds'/60/60%24}') && [ "$Hours" -gt 0 ] && Hours=$Hours小时 || Hours=""
			Minutes=$(awk BEGIN'{printf "%d\n",'$TotalSeconeds'/60%60}') && [ "$Minutes" -gt 0 ] && Minutes=$Minutes分 || Minutes=""
			Seconeds=$(awk BEGIN'{printf "%d\n",'$TotalSeconeds'%60}')秒
			states="$YELLOW运行时长：$PINK$Days$Hours$Minutes$Seconeds"
		else states="";fi
		echo -e "2.  $RED停止运行 ${BLUE}Clash-mihomo$RESET\t\t$states$RESET"
		[ "$common_ports" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "3.  $GREEN开启$RESET/$RED关闭 $SKYBLUE仅代理常用端口\t\t$YELLOW当前状态：$states$RESET"
		[ "$cnip_route" = "开" -o "$cnipv6_route" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "4.  $GREEN开启$RESET/$RED关闭 ${SKYBLUE}CNIP绕过内核\t\t$YELLOW当前状态：$states$RESET"
		[ "$Clash_Local_Proxy" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "5.  $GREEN开启$RESET/$RED关闭 $SKYBLUE本机流量代理\t\t$YELLOW当前状态：$states$RESET"
		[ "$Docker_Proxy" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "6.  $GREEN开启$RESET/$RED关闭 ${SKYBLUE}Docker流量代理\t\t$YELLOW当前状态：$states$RESET"
		[ "$dns_hijack" = "开" -o "$dnsipv6_hijack" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "7.  $GREEN开启$RESET/$RED关闭 ${SKYBLUE}DNS流量劫持\t\t$YELLOW当前状态：$states$RESET"
		[ "$mac_filter" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "8.  $GREEN开启$RESET/$RED关闭 $SKYBLUE常用设备过滤\t\t$YELLOW当前状态：$states$RESET"
		[ "$mac_filter_mode" = "黑名单" ] && states="$PINK黑名单" || states="$GREEN白名单"
		echo -e "9.  $YELLOW切换 $SKYBLUE常用设备过滤模式\t\t$YELLOW当前状态：$states$RESET"
		echo -e "10. $YELLOW查看 $SKYBLUE防火墙相关规则$RESET"
		[ "$(grep $config_url$ $CLASHDIR/config_url.ini)" ] && states="$BLUE$(grep $config_url$ $CLASHDIR/config_url.ini | sed 's/ http.*//')" || states="$SKYBLUE$config_url"
		echo -e "11. $YELLOW更新 $SKYBLUE订阅转换文件\t\t\t$YELLOW当前规则：$states$RESET"
		echo -e "12. $YELLOW更新 $SKYBLUE所有相关文件$RESET"
		[ "$(grep "$0 start$" /etc/rc.d/S99Clash_mihomo 2> /dev/null)" ] && states="$GREEN已开启" || states="$RED已关闭"
		echo -e "13. $YELLOW设置 $SKYBLUE开机自启动\t\t\t$YELLOW当前状态：$states$RESET"
		echo -e "88. $RED一键卸载 ${BLUE}Clash-mihomo $RED所有文件$RESET"
		[ "$mirrorserver" ] && states="$YELLOW正在使用：$SKYBLUE$mirrorserver" || states="$YELLOW当前状态：$RED已禁用"
		echo -e "99. $YELLOW切换 ${SKYBLUE}Github镜像加速下载服务器\t$states$RESET"
		echo "---------------------------------------------------------"
		echo -ne "\n"
		read -p "请输入对应选项的数字 > " num
	}
	case "$num" in
		1)
			start;;
		2)
			stop;;
		3)
			[ "$common_ports" = "开" ] && common_ports=关 || common_ports=开
			[ "$(pidof mihomo)" ] && startfirewall;main;;
		4)
			echo "========================================================="
			echo "请输入你的选项："
			echo "---------------------------------------------------------"
			[ "$cnip_route" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
			echo -e "1. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}CNIPv4绕过内核\t\t$YELLOW当前状态：$states$RESET"
			[ "$cnipv6_route" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
			echo -e "2. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}CNIPv6绕过内核\t\t$YELLOW当前状态：$states$RESET"
			echo "---------------------------------------------------------"
			echo "0. 返回上一页"
			echo -ne "\n"
			read -p "请输入对应选项的数字 > " cniproutenum
			case "$cniproutenum" in
				1)
					[ "$cnip_route" = "开" ] && cnip_route=关 || cnip_route=开
					[ "$(pidof mihomo)" ] && startfirewall;main $num;;
				2)
					[ "$cnipv6_route" = "开" ] && cnipv6_route=关 || cnipv6_route=开
					[ "$(pidof mihomo)" ] && startfirewall;main $num;;
				0)
					main;;
			esac;;
		5)
			[ "$Clash_Local_Proxy" = "开" ] && Clash_Local_Proxy=关 || Clash_Local_Proxy=开
			[ "$(pidof mihomo)" ] && startfirewall;main;;
		6)
			if [ "$(ip route | grep docker | awk '{print $1}' | head -1)" ];then
				[ "$Docker_Proxy" = "开" ] && Docker_Proxy=关 || Docker_Proxy=开
				[ "$(pidof mihomo)" ] && startfirewall
			else echo -e "\n$RED没有检测到 ${BLUE}Docker $RED正在运行！$RESET\n" && sleep 1;fi;main;;
		7)
			echo "========================================================="
			echo "请输入你的选项："
			echo "---------------------------------------------------------"
			[ "$dns_hijack" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
			echo -e "1. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}DNS IPv4流量劫持\t\t$YELLOW当前状态：$states$RESET"
			[ "$dnsipv6_hijack" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
			echo -e "2. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}DNS IPv6流量劫持\t\t$YELLOW当前状态：$states$RESET"
			echo "---------------------------------------------------------"
			echo "0. 返回上一页"
			echo -ne "\n"
			read -p "请输入对应选项的数字 > " dnshijacknum
			case "$dnshijacknum" in
				1)
					[ "$dns_hijack" = "开" ] && dns_hijack=关 || dns_hijack=开
					[ "$(pidof mihomo)" ] && startfirewall;main $num;;
				2)
					if [ "$routev6" -a "$dns_ipv6" = "开" -a "$(cat $CLASHDIR/config.yaml 2> /dev/null | grep '  ipv6:'| awk '{print $2}')" = "true" ];then
						[ "$dnsipv6_hijack" = "开" ] && dnsipv6_hijack=关 || dnsipv6_hijack=开
						[ "$(pidof mihomo)" ] && startfirewall
					else echo -e "\n$RED当前无法修改 ${SKYBLUE}DNS IPv6流量劫持 $RED选项！$RESET\n" && sleep 1;fi;main $num;;
				0)
					main;;
			esac;;
		8)
			[ "$mac_filter" = "开" ] && mac_filter=关 || mac_filter=开
			[ "$(pidof mihomo)" ] && startfirewall;main;;
		9)
			[ "$mac_filter_mode" = "黑名单" ] && mac_filter_mode=白名单 || mac_filter_mode=黑名单
			[ "$(pidof mihomo)" ] && startfirewall;main;;
		10)
			showfirewall;;
		11)
			[ ! "$confignum" ] && {
				echo "========================================================="
				echo "请输入你的选项："
				echo "---------------------------------------------------------"
				[ "$udp_support" = "开" ] && states="$GREEN已开启" || states="$RED已关闭"
				echo -e "1. $GREEN开启$RESET/$RED关闭 ${SKYBLUE}节点UDP支持功能\t\t$YELLOW当前状态：$states$RESET"
				[ "$(grep $sub_url$ $CLASHDIR/convert_server.ini)" ] && states="$BLUE$(grep $sub_url$ $CLASHDIR/convert_server.ini | sed 's/ http.*//')" || states="$SKYBLUE$sub_url"
				echo -e "2. $YELLOW切换 ${SKYBLUE}订阅转换服务器\t\t\t$YELLOW正在使用：$states$RESET"
				[ "$(grep $config_url$ $CLASHDIR/config_url.ini)" ] && states="$BLUE$(grep $config_url$ $CLASHDIR/config_url.ini | sed 's/ http.*//')" || states="$SKYBLUE$config_url"
				echo -e "3. $YELLOW切换 ${SKYBLUE}订阅转换规则\t\t\t$YELLOW正在使用：$states$RESET"
				echo "9. 立即更新订阅链接"
				echo "---------------------------------------------------------"
				echo "0. 返回上一页"
				echo -ne "\n"
				read -p "请输入对应选项的数字 > " confignum
			}
			case "$confignum" in
				1)
					[ "$udp_support" = "开" ] && udp_support=关 || udp_support=开;main $num;;
				2)
					echo "========================================================="
					echo "请输入你的选项："
					echo "---------------------------------------------------------"
					while read LINE;do [ "$LINE" ] && echo -e "$suburlcount. $LINE" | sed 's/ http.*//' && let suburlcount++;done < $CLASHDIR/convert_server.ini
					[ "$(grep $sub_url$ $CLASHDIR/convert_server.ini)" ] && states="$BLUE$(grep $sub_url$ $CLASHDIR/convert_server.ini | sed 's/ http.*//')" || states="$SKYBLUE$sub_url"
					echo -e "$suburlcount. 自定义输入后端服务器地址\t\t$YELLOW正在使用：$states$RESET"
					echo "---------------------------------------------------------"
					echo "0. 返回上一页"
					echo -ne "\n"
					read -p "请输入对应选项的数字 > " suburlnum
					case "$suburlnum" in
						$suburlcount)
							echo -ne "\n" && read -p "请输入或粘贴配置文件地址：" subserver_temp
							if [ "$(echo $subserver_temp | grep -E '^http://.*\.[^$]|^https://.*\.[^$]' )" ];then
								sub_url=$(echo $subserver_temp | awk '{print $1}') && main $num $confignum
							elif [ "$subserver_temp" ];then
								echo -e "\n$YELLOW请输入正确格式以http开头的服务器地址！$RESET\n" && sleep 1 && main $num $confignum
							fi;;
						0)
							main $num;;
					esac
					[ "$suburlnum" -a ! "$(echo $suburlnum | sed 's/[0-9]//g')" ] && [ "$suburlnum" -lt "$suburlcount" ] && sub_url="$(sed -n "${suburlnum}p" $CLASHDIR/convert_server.ini | grep -o http.*)" && main $num $confignum;;
				3)
					echo "========================================================="
					echo "请输入你的选项："
					echo "---------------------------------------------------------"
					while read LINE;do [ "$LINE" ] && echo -e "$configurlcount. $LINE" | sed 's/ http.*//' && let configurlcount++;done < $CLASHDIR/config_url.ini
					[ "$(grep $config_url$ $CLASHDIR/config_url.ini)" ] && states="$BLUE$(grep $config_url$ $CLASHDIR/config_url.ini | sed 's/ http.*//')" || states="$SKYBLUE$config_url"
					echo -e "$configurlcount. 自定义输入配置规则地址\t\t$YELLOW正在使用：$states$RESET"
					echo "---------------------------------------------------------"
					echo "0. 返回上一页"
					echo -ne "\n"
					read -p "请输入对应选项的数字 > " configurlnum
					case "$configurlnum" in
						$configurlcount)
							echo -ne "\n" && read -p "请输入或粘贴配置文件地址：" configserver_temp
							if [ "$(echo $configserver_temp | grep -E '^http://.*\.[^$]|^https://.*\.[^$]' )" ];then
								config_url=$(echo $configserver_temp | awk '{print $1}') && main $num $confignum
							elif [ "$configserver_temp" ];then
								echo -e "\n$YELLOW请输入正确格式以http开头的服务器地址！$RESET\n" && sleep 1 && main $num $confignum
							fi;;
						0)
							main $num;;
					esac
					[ "$configurlnum" -a ! "$(echo $configurlnum | sed 's/[0-9]//g')" ] && [ "$configurlnum" -lt "$configurlcount" ] && config_url="$(sed -n "${configurlnum}p" $CLASHDIR/config_url.ini | grep -o http.*)" && main $num $confignum;;
				9)
					mv -f $CLASHDIR/config_original.yaml $CLASHDIR/config_original.yaml.backup 2> /dev/null;stop && start;;
				0)
					main;;
			esac;;
		12)
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
			echo -ne "\n"
			read -p "请输入对应选项的数字 > " deletenum
			case "$deletenum" in
				1)
					stop;stop del;stop del
					sed -i '/clash=/d' /etc/profile && sed -i '/./,/^$/!d' /etc/profile && sed -i '/Clash/d' /etc/passwd && rm -rf $CLASHDIR /etc/init.d/Clash_mihomo /etc/rc.d/S99Clash_mihomo && echo -e "\n${BLUE}Clash-mihomo $RED已一键卸载！请重进SSH清除clash命令变量环境！再会！$RESET";;
				0)
					main;;
			esac;;
		99)
			echo "========================================================="
			[ "$mirrorserver" ] && states="$YELLOW正在使用：$SKYBLUE$mirrorserver" || states="$YELLOW当前状态：$RED已禁用"
			echo -e "请输入你的选项：\t\t\t$states$RESET"
			echo "---------------------------------------------------------"
			while read LINE;do [ "$LINE" ] && echo -e "$mirrorurlcount. $LINE" | awk '{print $1,$2}' && let mirrorurlcount++;done < $CLASHDIR/mirror_server.ini
			echo "$mirrorurlcount. 自定义输入服务器地址（如需禁用加速下载功能请选此项然后直接回车确定）"
			echo "---------------------------------------------------------"
			echo "0. 返回上一页"
			echo -ne "\n"
			read -p "请输入对应选项的数字 > " mirrorurlnum
			[ "$mirrorurlnum" = 0 ] && main
			[ "$mirrorurlnum" = "$mirrorurlcount" ] && {
				echo -ne "\n" && read -p "请输入或粘贴加速镜像服务器地址：" mirrorserver_temp
				if [ "$mirrorserver_temp" ];then
					if [ "$(echo $mirrorserver_temp | grep -E '^http://.*\.|^https://.*\.' )" ];then
						mirrorserver=$(echo $mirrorserver_temp | awk '{print $1}') && main $num
					else
						echo -e "\n$YELLOW请输入正确格式以http开头的服务器地址！$RESET\n" && sleep 1 && main $num
					fi
				else
					mirrorserver="" && echo -e "\n$YELLOW已禁用 ${SKYBLUE}Github镜像加速下载功能 $YELLOW！$RESET\n" && sleep 1 && main $num
				fi
			}
			[ "$mirrorurlnum" -a ! "$(echo $mirrorurlnum | sed 's/[0-9]//g')" ] && [ "$mirrorurlnum" -lt "$mirrorurlcount" ] && mirrorserver="$(sed -n "${mirrorurlnum}p" $CLASHDIR/mirror_server.ini | awk '{print $1}')" && main $num;;
	esac
}
case "$1" in
	1|start)start;;
	2|stop)stop;;
	10|showfirewall)showfirewall;;
	11|config_update)mv -f $CLASHDIR/config_original.yaml $CLASHDIR/config_original.yaml.backup 2> /dev/null;stop && start;;
	12|update)update;;
	crontab)update crontab;;
	startfirewall)startfirewall;;
	*)main;;
esac
