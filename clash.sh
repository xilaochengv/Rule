CLASHDIR=$(dirname $0) && [ -s $CLASHDIR/config.ini ] && . $CLASHDIR/config.ini
RED='\e[0;31m';GREEN='\e[1;32m';YELLOW='\e[1;33m';BLUE='\e[1;34m';PINK='\e[1;35m';SKYBLUE='\e[1;36m';RESET='\e[0m'
sed -i '/clash=/d' /etc/profile && echo -e "\nexport CLASHDIR=$(dirname $0);alias clash=\"$0\"" >> /etc/profile && sed -i '/./,/^$/!d' /etc/profile
route=$(ip route | grep br-lan | awk {'print $1'})
routes="127.0.0.0/8 $route"
routev6=$(ip -6 route | grep br-lan | awk '{print $1}')
routesv6="::1/128 $routev6"
localip=$(ip route | grep br-lan | awk {'print $9'})
wanipv4=$(ip -o addr | grep pppoe-wan | grep 'inet ' | awk '{print $4}')
wanipv6=$(ip -o addr | grep pppoe-wan | grep inet6.*global | sed -e 's/.*inet6 //' -e 's#/.*##')
[ ! "$sublink" ] && sublink='订阅链接|多个订阅地址请用|竖线分割'
[ ! "$exclude" ] && exclude='节点过滤|多个关键字请用|竖线分割'
[ ! "$udp_support" ] && udp_support=关
[ ! "$(echo $config_url | grep ^http)" ] && config_url=https://raw.githubusercontent.com/xilaochengv/Rule/main/rule.ini
[ ! "$geoip_url" ] && geoip_url=https://github.com/xilaochengv/Rule/releases/download/Latest/geoip.dat
[ ! "$geosite_url" ] && geosite_url=https://github.com/xilaochengv/Rule/releases/download/Latest/geosite.dat
[ ! "$redir_port" ] && redir_port=25274
[ ! "$dashboard_port" ] && dashboard_port=6789
[ ! "$core_ipv6" -o ! "$routev6" ] && core_ipv6=关
[ ! "$dns_ipv6" -o ! "$routev6" ] && dns_ipv6=关
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
[ ! "$wakeonlan_ports" ] && wakeonlan_ports=9
[ ! "$Docker_Proxy" -o ! "$(ip route | grep docker | awk '{print $1}' | head -1)" ] && Docker_Proxy=关
[ ! "$Clash_Local_Proxy" ] && Clash_Local_Proxy=关
[ -s $CLASHDIR/custom_rules.ini ] || echo -e "#说明文档：https://wiki.metacubex.one/config/rules\n#填写格式：\n#DOMAIN,baidu.com,DRIECT（不需要填前面的-符号）" > $CLASHDIR/custom_rules.ini
[ ! "$(grep ^http $CLASHDIR/mirror_server.ini 2> /dev/null)" ] && echo -e "https://gh.ddlc.top\nhttps://mirror.ghproxy.com\nhttps://hub.gitmirror.com" > $CLASHDIR/mirror_server.ini
[ ! "$(grep http $CLASHDIR/config_url.ini 2> /dev/null)" ] && echo -e "作者自用GEO精简规则 https://raw.githubusercontent.com/xilaochengv/Rule/main/rule.ini\n默认版规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini\n精简版规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini\n更多去广告规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_AdblockPlus.ini\n多国分组规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_MultiCountry.ini\n无自动测速规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoAuto.ini\n无广告拦截规则 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoReject.ini\n全分组规则 重度用户使用 https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini" > $CLASHDIR/config_url.ini
Filesystem=$(dirname $0);while [ ! "$(df $Filesystem)" ];do Filesystem=$(echo ${Filesystem%/*});done;Filesystem=$(df $Filesystem | tail -1 | awk '{print $6}');Available=$(df $Filesystem | tail -1 | awk '{print $4}')
[ ! -f $CLASHDIR/mihomo -a $Available -lt 17000 ] && echo -e "$RED当前分区 $BLUE$Filesystem $RED空间不足！请更换本脚本存放位置！$RESET" && exit
start(){
	stop start && update missingfiles
	[ "$core_ipv6" = "开" ] && ipv6_core=true || ipv6_core=false
	[ "$dns_ipv6" = "开" ] && ipv6_dns=true || ipv6_dns=false
	cat > $CLASHDIR/config.yaml << EOF
redir-port: $redir_port
mixed-port: $(($redir_port+1))
allow-lan: true
authentication:
  - "username:password"
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
	echo -e "while [ true ];do\n\tsleep 1\n\t[ \$(awk 'NR==3{print \$2}' /proc/meminfo) -lt 102400 ] && curl -so /dev/null \"http://127.0.0.1:$dashboard_port/debug/gc\" -X PUT\ndone" > /tmp/autooc.sh && chmod 755 /tmp/autooc.sh && /tmp/autooc.sh &
	echo -e "\n${BLUE}Clash-mihomo $GREEN启动成功！$YELLOW面板管理页面：$SKYBLUE$localip:$dashboard_port/ui$RESET\n"
	#修复小米AX9000开启QOS功能情况下某些特定udp端口（如80 8080等）流量无法通过问题
	[ "$(uci get /usr/share/xiaoqiang/xiaoqiang_version.version.HARDWARE 2> /dev/null)" = "RA70" ] && [ -d /sys/module/shortcut_fe_cm ] && rmmod shortcut-fe-cm &> /dev/null
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
	echo "exclude='$exclude'" >> $CLASHDIR/config.ini
	echo "udp_support=$udp_support" >> $CLASHDIR/config.ini
	echo "mirrorserver='$mirrorserver'" >> $CLASHDIR/config.ini
	echo "config_url='$config_url'" >> $CLASHDIR/config.ini
	echo "geoip_url='$geoip_url'" >> $CLASHDIR/config.ini
	echo "geosite_url='$geosite_url'" >> $CLASHDIR/config.ini
	echo -e "\n#修改以下配置前，必须先运行脚本并选择2停止Clash-mihomo！否则修改前的防火墙规则无法清理干净！" >> $CLASHDIR/config.ini
	echo "redir_port=$redir_port" >> $CLASHDIR/config.ini
	echo -e "\n#以下配置修改后，需要重启Clash-mihomo后才能生效" >> $CLASHDIR/config.ini
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
	echo "multiports=$multiports" >> $CLASHDIR/config.ini
	echo "wakeonlan_ports=$wakeonlan_ports" >> $CLASHDIR/config.ini
	echo "dns_server_ip_filter='$dns_server_ip_filter'" >> $CLASHDIR/config.ini
	[ ! "$(echo $sublink | grep //)" ] && echo -e "$RED请先在 $SKYBLUE$CLASHDIR/config.ini $RED文件中填写好订阅链接地址！$YELLOW（现在退出并重进SSH即可直接使用clash命令）$RESET" && exit
	return 0
}
githubdownload(){
	url=$4 && [ "$(echo $url | grep -vE '/http|=http' | grep -E 'github.com/|githubusercontent.com/')" ] && url="$(echo $url | sed "s#.*#$(echo $mirrorserver | sed 's/[^/]$/&\//')&#")"
	rm -f $1 && [ "$3" ] && echo -e "\n$YELLOW下载$3 $SKYBLUE$url $YELLOW······$RESET \c"
	[ "$(curl -m 10 -sLko $1 "$url" -w "%{http_code}")" != "200" ] && rm -f $1 && return 1
	[ -f $1 -a "$2" ] && [ $(wc -c < $1) -lt $2 ] && rm -f $1 && return 1
	[ "$3" ] && echo -e "$GREEN下载成功！$RESET";return 0
}
subconver(){
	rm -f $CLASHDIR/proxies_temp.yaml $CLASHDIR/proxy_groups_temp.yaml $CLASHDIR/rules_temp.yaml $CLASHDIR/config_temp.ini $CLASHDIR/sub_original $CLASHDIR/sub_temp
	for url in $(echo $sublink | sed 's/|/ /g');do
		[ "$(echo $url | grep //)" ] && echo -e "\n$YELLOW下载订阅链接 $SKYBLUE$url $YELLOW···$RESET \c" && curl -skLo $CLASHDIR/sub_original -m 60 $url
		if [ $? = 0 ];then base64 -d $CLASHDIR/sub_original >> $CLASHDIR/sub_temp && echo -e "$GREEN下载成功！$RESET";else echo -e "$RED下载失败！已自动退出脚本$RESET";exit;fi
	done
	[ "$(echo $config_url | grep //)" ] && githubdownload "$CLASHDIR/config_temp.ini" "" "订阅配置文件" "$config_url"
	[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	[ ! "$(grep ^proxies: $CLASHDIR/proxies_temp.yaml 2> /dev/null)" ] && echo "proxies:" > $CLASHDIR/proxies_temp.yaml
	while read LINE;do
		password=""
		type=$(echo $LINE | cut -d : -f 1)
		server=$(echo $LINE | grep -o '@.*:' | sed 's/[@:]//g')
		port=$(echo $LINE | grep -oE ':[0-9]{1,5}' | sed 's/://')
		passwordtemp=$(echo $LINE | grep -o '/.*@' | sed 's/[/@]//g')
		sni=$(echo $LINE | grep -oE 'sni=.*[#&]' | sed 's/sni=//;s/[#&].*//')
		name=$(printf $(echo $LINE | cut -d \# -f 2 | sed 's/\\/\\\\/g;s/\(%\)\([0-9a-fA-F][0-9a-fA-F]\)/\\x\2/g') | sed "s/.$//")
		[ "$type" = "trojan" ] && password=", password: $passwordtemp"
		[ "$type" = "hysteria2" ] && password=", password: $passwordtemp, auth: $passwordtemp"
		[ "$type" = "ss" ] && passwordtemp=$(echo $passwordtemp | base64 -d 2> /dev/null) && [ $? = 0 ] && password=", cipher: $(echo $passwordtemp | cut -d : -f 1), password: $(echo $passwordtemp | cut -d : -f 2)"
		[ "$udp_support" = "开" ] && udp=", udp: true"
		[ "$sni" ] && sni=", sni: $sni, skip-cert-verify: true"
		if [ "$(echo $name | grep -E "$exclude")" ];then echo -e "\n$YELLOW过滤节点：$PINK$name $YELLOW根据关键字自动过滤$RESET";else [ "$password" ] && echo "  - {name: $name, server: $server, port: $port, client-fingerprint: chrome, type: $type$password$sni$udp}" >> $CLASHDIR/proxies_temp.yaml && echo -e "\n$GREEN添加节点：$PINK$name $GREEN成功！节点类型：$PINK$type$RESET" && proxies="$proxies\n$name" || echo -e "\n$RED添加节点：$PINK$name $RED失败！已自动过滤$RESET";fi
	done < $CLASHDIR/sub_temp
	[ ! "$(grep ^proxy-groups: $CLASHDIR/proxy_groups_temp.yaml 2> /dev/null)" ] && echo "proxy-groups:" > $CLASHDIR/proxy_groups_temp.yaml
	cat $CLASHDIR/config_temp.ini | grep ^custom_proxy_group | while read LINE;do
		name=$(echo $LINE | cut -d = -f 2 | awk -F \` '{print $1}')
		type=$(echo $LINE | cut -d = -f 2 | awk -F \` '{print $2}')
		groups=$(echo $LINE | cut -d = -f 2 | awk -F \` '{$1="";$2="";print $0}' | sed 's/^  //;s/\.\*/[]allproxy/;s/ /\#/g;s/\[]/ &/g;s/(.*/ &/')
		echo "  - name: $name" >> $CLASHDIR/proxy_groups_temp.yaml && echo -e "\n$GREEN代理组：$PINK$name $GREEN包含节点（代理组）：$RESET\c"
		echo "    type: $type" >> $CLASHDIR/proxy_groups_temp.yaml
		[ "$(echo $LINE | grep //)" ] && {
			echo "    url: $(echo $LINE | cut -d \` -f 4)" >> $CLASHDIR/proxy_groups_temp.yaml
			echo "    interval: $(echo $LINE | cut -d \` -f 5 | awk -F , '{print $1}')" >> $CLASHDIR/proxy_groups_temp.yaml
			echo "    tolerance: $(echo $LINE | cut -d \` -f 5 | awk -F , '{print $3}')" >> $CLASHDIR/proxy_groups_temp.yaml
		}
		echo "    proxies:" >> $CLASHDIR/proxy_groups_temp.yaml
		for group in $groups;do
			if [ "$(echo $group | grep allproxy)" ];then
				echo -e "$proxies" | while read LINE;do
					[ "$LINE" ] && echo "      - $LINE" >> $CLASHDIR/proxy_groups_temp.yaml && echo -e "$PINK$LINE$RESET \c"
				done
			elif [ "$(echo $group | grep \()" ];then
				echo -e "$proxies" | grep -E "$(echo $group | sed 's/[()]//g')" | while read LINE;do echo "      - $LINE" >> $CLASHDIR/proxy_groups_temp.yaml && echo -e "$PINK$LINE$RESET \c";done
			else
				echo "      - $group" | grep -v // | sed 's/\[]//g;s/#/ /g;s/ $//g' >> $CLASHDIR/proxy_groups_temp.yaml && echo -e "$PINK$(echo $group | grep -v // | sed 's/\[]//g;s/#/ /g;s/ $//g')$RESET \c"
			fi
		done;echo
	done
	echo "rules:" >> $CLASHDIR/proxy_groups_temp.yaml
	for group in $(sed -n '/  - name: /p' $CLASHDIR/proxy_groups_temp.yaml | sed 's/ /#/g');do
		[ ! "$(sed -n "/$(echo $group | sed 's/#/ /g')/,/  -.*:/p" $CLASHDIR/proxy_groups_temp.yaml | head -n -1 | grep -E '^      -')" ] && {
			delgroupendline=$(sed -n "/$(echo $group | sed 's/#/ /g')/,/  -.*:/=" $CLASHDIR/proxy_groups_temp.yaml | head -n -1 | tail -1)
			delgroupstartline=$(sed -n "/$(echo $group | sed 's/#/ /g')/,/  -.*:/=" $CLASHDIR/proxy_groups_temp.yaml | head -n -1 | head -1)
			sed -i "$delgroupstartline,$delgroupendline d;/$(echo $group | awk -F \# '{print $NF}')/d" $CLASHDIR/proxy_groups_temp.yaml
			echo -e "\n$YELLOW代理组：$PINK$(echo $group | awk -F \# '{print $NF}') $YELLOW内无内容，已自动过滤$RESET"
		}
	done
	[ -s $CLASHDIR/config_temp.ini ] && cat $CLASHDIR/config_temp.ini | grep ^ruleset | while read LINE;do
		[ "$(echo $LINE | grep -oiE 'geoip.*|geosite.*|match.*|final.*')" ] && echo "  - $(echo $LINE | grep -oiE 'geoip.*|geosite.*|match.*|final.*' | sed 's/final/MATCH/i'),$(echo $LINE | cut -d = -f 2 | awk -F , '{print $1}')" >> $CLASHDIR/rules_temp.yaml
		[ "$(echo $LINE | grep //)" ] && {
			rulesurl=$(echo $LINE | awk -F , '{print $2}') && [ "$(echo $rulesurl | grep -vE '/http|=http' | grep -E 'github.com/|githubusercontent.com/')" ] && rulesurl="$(echo $rulesurl | sed "s#.*#$(echo $mirrorserver | sed 's/[^/]$/&\//')&#")"
			groupsname=$(echo $LINE | cut -d = -f 2 | awk -F , '{print $1}')
			echo -e "\n$YELLOW下载 $BLUE$groupsname $YELLOW代理组规则 $SKYBLUE$rulesurl $YELLOW···$RESET \c"
			curl -skLm 5 $rulesurl -w "%{http_code}\n" | grep -vE '^$|\#|USER-AGENT|URL-REGEX' | sed "s/,no-resolve//;s/.*/  - &,$groupsname/" | sed 's/IP-CIDR.*/&,no-resolve/' >> $CLASHDIR/rules_temp.yaml
			if [ "$(sed -n '$p' $CLASHDIR/rules_temp.yaml | grep "200")" ];then
				echo -e "$GREEN下载成功！$RESET"
			else
				echo -e "$RED下载失败！$RESET"
			fi
			sed -i '$d' $CLASHDIR/rules_temp.yaml
		}
	done
	for char in proxies proxy_groups rules;do cat $CLASHDIR/${char}_temp.yaml >> $CLASHDIR/config_original.yaml;done
	rm -f $CLASHDIR/proxies_temp.yaml $CLASHDIR/proxy_groups_temp.yaml $CLASHDIR/rules_temp.yaml $CLASHDIR/config_temp.ini $CLASHDIR/sub_original $CLASHDIR/sub_temp
	echo -e "\n$YELLOW订阅链接本地转换结束$RESET"
}
update(){
	[ ! "$1" ] && stop && rm -rf $CLASHDIR/ui $CLASHDIR/cn_ip.txt $CLASHDIR/cn_ipv6.txt $CLASHDIR/config.yaml $CLASHDIR/config_original.yaml $CLASHDIR/GeoIP.dat $CLASHDIR/GeoSite.dat $CLASHDIR/mihomo
	[ ! -d $CLASHDIR/ui ] && {
		githubdownload "/tmp/dashboard" "300000" "Meta基础面板" "https://raw.githubusercontent.com/juewuy/ShellCrash/dev/bin/dashboard/meta_db.tar.gz"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
		mkdir -m 755 $CLASHDIR/ui && tar -zxf /tmp/dashboard -C $CLASHDIR/ui && rm -f /tmp/dashboard
		sed -i "s/9090/$dashboard_port/g;s/127.0.0.1/$localip/g" $CLASHDIR/ui/assets/index.628acf3b.js
	}
	[ ! -f $CLASHDIR/mihomo ] && {
		while [ ! "$latestversion" ];do latestversion=$(curl --connect-timeout 3 -sk "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" | grep tag_name | cut -f4 -d '"');done
		githubdownload "/tmp/mihomo.gz" "9500000" "Clash主程序文件" "https://github.com/MetaCubeX/mihomo/releases/download/$latestversion/mihomo-linux-arm64-$latestversion.gz"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
		rm -f $CLASHDIR/mihomo /tmp/mihomo && gzip -d /tmp/mihomo.gz && mv -f /tmp/mihomo $CLASHDIR/mihomo && chmod 755 $CLASHDIR/mihomo
	}
	[ ! -f $CLASHDIR/config_original.yaml ] && subconver
	[ ! -f $CLASHDIR/cn_ip.txt -a "$cnip_route" = "开" ] && {
		githubdownload "$CLASHDIR/cn_ip.txt" "130000" "CN-IP数据库文件" "https://github.com/xilaochengv/Rule/releases/download/Latest/cn_ip.txt"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ ! -f $CLASHDIR/cn_ipv6.txt -a "$core_ipv6" = "开" -a "$cnipv6_route" = "开" ] && {
		githubdownload "$CLASHDIR/cn_ipv6.txt" "29000" "CN-IPV6数据库文件" "https://github.com/xilaochengv/Rule/releases/download/Latest/cn_ipv6.txt"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ ! -f $CLASHDIR/GeoIP.dat ] && {
		githubdownload "$CLASHDIR/GeoIP.dat" "" "GeoIP数据库文件" "$geoip_url"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
	[ ! -f $CLASHDIR/GeoSite.dat ] && {
		githubdownload "$CLASHDIR/GeoSite.dat" "" "GeoSite数据库文件" "$geosite_url"
		[ $? != 0 ] && echo -e "$RED下载失败！已自动退出脚本！$RESET" && exit
	}
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
		if [ "$(grep -v '^ *#' $CLASHDIR/maclist.ini 2> /dev/null)" ];then
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
		iptables -t nat -A PREROUTING -p udp --dport 53 -m comment --comment "DNS流量进入Clash_DNS规则链" -j Clash_DNS
		iptables -t nat -I OUTPUT -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash_DNS规则链" -j Clash_DNS
		iptables -t nat -A Clash_DNS -d $localip -p udp --dport 53 -m comment --comment "DNS流量进入Clash内核" -j REDIRECT --to-ports $dns_port
		iptables -t nat -A Clash_DNS -d 127.0.0.1 -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash内核" -j REDIRECT --to-ports $dns_port
	}
	[ "$dnsipv6_hijack" = "开" ] && {
		ip6tables -t nat -N Clash_DNS
		ip6tables -t nat -A PREROUTING -p udp --dport 53 -m comment --comment "DNS流量进入Clash_DNS规则链" -j Clash_DNS
		ip6tables -t nat -I OUTPUT -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash_DNS规则链" -j Clash_DNS
		for route6 in $routev6;do
			ip6tables -t nat -A Clash_DNS -d $route6 -p udp --dport 53 -m comment --comment "DNS流量进入Clash内核" -j REDIRECT --to-ports $dns_port
		done
		ip6tables -t nat -A Clash_DNS -d ::1/128 -p udp --dport 53 -m comment --comment "DNS本机流量进入Clash内核" -j REDIRECT --to-ports $dns_port
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
	echo -e "\n----------------------------------------IPv6  MANGLE----------------------------------------" && {
		[ "$(ip6tables -t mangle -S PREROUTING | grep Clash)" ] && ip6tables -t mangle -nvL PREROUTING && echo && ip6tables -t mangle -nvL Clash
	}
	echo -e "\n-----------------------------------------IPv6  NAT------------------------------------------" && {
		[ "$(ip6tables -t nat -S PREROUTING | grep Clash)" ] && ip6tables -t nat -nvL PREROUTING && echo && ip6tables -t nat -nvL Clash 2> /dev/null
		[ "$(ip6tables -t nat -S OUTPUT | grep Clash)" ] && echo && ip6tables -t nat -nvL OUTPUT && echo && {
			ip6tables -t nat -nvL Clash_DNS 2> /dev/null && echo
			ip6tables -t nat -nvL Clash_Local_Proxy 2> /dev/null
		}
	}
	echo -e "\n----------------------------------------IPv6  FILTER----------------------------------------" && {
		[ "$(ip6tables -S FORWARD | grep utun)" ] && ip6tables -nvL FORWARD
	}
}
#修复小米AX9000开启QOS时若Clash-mihomo正在运行而导致某些特定udp端口流量（如80 8080等）无法通过问题
[ "$(uci get /usr/share/xiaoqiang/xiaoqiang_version.version.HARDWARE 2> /dev/null)" = "RA70" ] && \
sed -i "s@\[ -d /sys/module/shortcut_fe_cm ] |@\[ -d /sys/module/shortcut_fe_cm -o -n \"\$(pidof mihomo)\" ] |@" /etc/init.d/shortcut-fe
main(){
	cniproutenum="" && dnshijacknum="" && configurlcount=1 && configurlnum="" && configserver_temp="" && deletenum="" && mirrorurlcount=1 && mirrorurlnum="" && mirrorserver_temp=""
	saveconfig && num="$1" && [ ! "$num" ] && {
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
		[ "$udp_support" = "开" ] && states="${YELLOW}UDP支持：$GREEN已开启" || states="${YELLOW}UDP支持：$RED已关闭"
		[ "$(grep $config_url$ $CLASHDIR/config_url.ini)" ] && states="$states\t$YELLOW当前规则：$BLUE$(grep $config_url$ $CLASHDIR/config_url.ini | sed 's/http.*//')" || states="$states\t$YELLOW当前规则：$SKYBLUE$config_url"
		echo -e "11. $YELLOW更新 $SKYBLUE订阅转换文件\t$states$RESET"
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
		1)start;;
		2)stop;;
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
			echo -e "0. 返回上一页"
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
				0)main;;
			esac;;
		8)
			[ "$mac_filter" = "开" ] && mac_filter=关 || mac_filter=开
			[ "$(pidof mihomo)" ] && startfirewall;main;;
		9)
			[ "$mac_filter_mode" = "黑名单" ] && mac_filter_mode=白名单 || mac_filter_mode=黑名单
			[ "$(pidof mihomo)" ] && startfirewall;main;;
		10)showfirewall;;
		11)
			echo "========================================================="			
			[ "$udp_support" = "开" ] && states="${YELLOW}UDP支持：$GREEN已开启" || states="${YELLOW}UDP支持：$RED已关闭"
			[ "$(grep $config_url$ $CLASHDIR/config_url.ini)" ] && states="$states\t$YELLOW当前规则：$BLUE$(grep $config_url$ $CLASHDIR/config_url.ini | sed 's/http.*//')" || states="$states\t$YELLOW当前规则：$SKYBLUE$config_url"
			echo -e "请输入你的选项：$states$RESET"
			echo "---------------------------------------------------------"
			while read LINE;do [ "$LINE" ] && echo -e "$configurlcount. $LINE" | sed 's/http.*//' && let configurlcount++;done < $CLASHDIR/config_url.ini
			echo -e "$configurlcount. 自定义输入配置规则地址（如需开启UDP支持请选此项然后输入udp回车确定）"
			echo -e "99. 立即更新订阅链接"
			echo "---------------------------------------------------------"
			echo -e "0. 返回上一页"
			echo -ne "\n"
			read -p "请输入对应选项的数字 > " configurlnum
			[ "$configurlnum" = 99 ] && rm -f $CLASHDIR/config_original.yaml && stop && start
			[ "$configurlnum" = 0 ] && main
			[ "$configurlnum" = "$configurlcount" ] && {
				echo -ne "\n" && read -p "请输入或粘贴配置文件地址：" configserver_temp
				[ "$configserver_temp" ] && {
					if [ "$(echo $configserver_temp | grep -E '^http://.*\.|^https://.*\.' )" ];then
						config_url=$(echo $configserver_temp | awk '{print $1}') && main $num
					elif [ "$configserver_temp" = "udp" ];then
						[ "$udp_support" = "开" ] && udp_support=关 || udp_support=开;main $num
					else
						echo -e "\n$YELLOW请输入以http开头的正确格式服务器地址！$RESET\n" && sleep 1 && main $num
					fi
				}
			}
			[ "$configurlnum" -a ! "$(echo $configurlnum | sed 's/[0-9]//g')" ] && [ "$configurlnum" -lt "$configurlcount" ] && config_url="$(sed -n "${configurlnum}p" $CLASHDIR/config_url.ini | grep -o http.*)" && main $num;;
		12)update;;
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
			echo -e "0. 返回上一页"
			echo -ne "\n"
			read -p "请输入对应选项的数字 > " deletenum
			case "$deletenum" in
				1)
					stop;stop del;stop del
					sed -i '/clash=/d' /etc/profile && sed -i '/./,/^$/!d' /etc/profile && sed -i '/Clash/d' /etc/passwd && rm -rf $CLASHDIR && echo -e "\n${BLUE}Clash-mihomo $RED已一键卸载！请重进SSH清除clash命令变量环境！再会！$RESET";;
				0)main;;
			esac;;
		99)
			echo "========================================================="
			[ "$mirrorserver" ] && states="$YELLOW正在使用：$SKYBLUE$mirrorserver" || states="$YELLOW当前状态：$RED已禁用"
			echo -e "请输入你的选项：\t\t\t$states$RESET"
			echo "---------------------------------------------------------"
			while read LINE;do [ "$LINE" ] && echo -e "$mirrorurlcount. $LINE" | awk '{print $1,$2}' && let mirrorurlcount++;done < $CLASHDIR/mirror_server.ini
			echo -e "$mirrorurlcount. 自定义输入服务器地址（如需禁用加速下载功能请选此项然后直接回车确定）"
			echo "---------------------------------------------------------"
			echo -e "0. 返回上一页"
			echo -ne "\n"
			read -p "请输入对应选项的数字 > " mirrorurlnum
			[ "$mirrorurlnum" = 0 ] && main
			[ "$mirrorurlnum" = "$mirrorurlcount" ] && {
				echo -ne "\n" && read -p "请输入或粘贴加速镜像服务器地址：" mirrorserver_temp
				if [ "$mirrorserver_temp" ];then
					if [ "$(echo $mirrorserver_temp | grep -E '^http://.*\.|^https://.*\.' )" ];then
						mirrorserver=$(echo $mirrorserver_temp | awk '{print $1}') && main $num
					else
						echo -e "\n$YELLOW请输入以http开头的正确格式服务器地址！$RESET\n" && sleep 1 && main $num
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
	11|config_update)rm -f $CLASHDIR/config_original.yaml;stop && start;;
	12|update)update;;
	*)main;;
esac
