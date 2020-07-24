#!/bin/bash
##======================================================================#
#				定义字体变量				#
#=======================================================================#

#fonts color
Green="\033[32m"
Red="\033[31m"
# Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"
#notification information
# Info="${Green}[信息]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

# 定义trojan用到的变量
Trojan_Passwd=`cat /dev/urandom | head -1 | md5sum | head -c 12`
Cert_Path="/etc/letsencrypt/live/certificate.crt"
Key_Path="/etc/letsencrypt/live/private.key"

#=======================================================================#
#				判断系统环境				#
#=======================================================================#
timedatectl set-timezone Asia/Shanghai #修改服务器时区，因为acme更新证书的时间是凌晨三点，
#如果不改为大陆区时间，那每天下午三点都会中断一次
source '/etc/os-release'

#从VERSION中提取发行版系统的英文名称，为了在debian/ubuntu下添加相对应的Nginx apt源
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
        Systempwd="/usr/lib/systemd/system/"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        Systempwd="/lib/systemd/system/"
        $INS update -y && $INS upgrade -y
        ## 添加 Nginx apt源
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        $INS update -y && $INS upgrade -y
    else
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
        exit 1
    fi
}
#判断目前是否为root用户
is_root() {
    if [ 0 == $UID ]; then
        echo -e "${OK} ${GreenBG} 当前用户是root用户，进入安装流程 ${Font}"
        sleep 3
    else
        echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}"
        exit 1
    fi
}

judge() {
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 失败${Font}"
        exit 1
    fi
}

##======================================================================##
##				安装依赖包				##
##======================================================================##

dependency_install() {
    ${INS} install wget git lsof socat nginx unzip zip -y 

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install cronie xz nano
    else
        ${INS} -y install cron libcap2-bin xz-utils neovim 
    fi
    judge "安装 crontab"

    if [[ "${ID}" == "centos" ]]; then
        touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
        systemctl start crond && systemctl enable crond
    else
        touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
        systemctl start cron && systemctl enable cron

    fi
    judge "crontab 自启动配置 "

    ${INS} -y install bc
    judge "安装 bc"

    ${INS} -y install curl
    judge "安装 curl"

    #if [[ "${ID}" == "centos" ]]; then
    #    ${INS} -y groupinstall "Development tools"
    #else
    #    ${INS} -y install build-essential
    #fi
    #judge "编译工具包 安装"


    #    ${INS} -y install rng-tools
    #    judge "rng-tools 安装"

    ${INS} -y install haveged
    #    judge "haveged 安装"

    #    sed -i -r '/^HRNGDEVICE/d;/#HRNGDEVICE=\/dev\/null/a HRNGDEVICE=/dev/urandom' /etc/default/rng-tools

    if [[ "${ID}" == "centos" ]]; then
        #       systemctl start rngd && systemctl enable rngd
        #       judge "rng-tools 启动"
        systemctl start haveged && systemctl enable haveged
        #       judge "haveged 启动"
    else
        #       systemctl start rng-tools && systemctl enable rng-tools
        #       judge "rng-tools 启动"
        systemctl start haveged && systemctl enable haveged
        #       judge "haveged 启动"
    fi
}

#========================================================================#
#				域名检测				 #
#========================================================================#

domain_check() {
    read -rp "请输入你的域名信息(eg:www.wulabing.com):" domain
    domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    echo -e "${OK} ${GreenBG} 正在获取 公网ip 信息，请耐心等待 ${Font}"
    local_ip=$(curl -4 ip.sb)
    echo -e "域名dns解析IP：${domain_ip}"
    echo -e "本机IP: ${local_ip}"
    sleep 2
    if [[ $(echo "${local_ip}" | tr '.' '+' | bc) -eq $(echo "${domain_ip}" | tr '.' '+' | bc) ]]; then
        echo -e "${OK} ${GreenBG} 域名dns解析IP 与 本机IP 匹配 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} 请确保域名添加了正确的 A 记录，否则将无法正常使用 V2ray ${Font}"
        echo -e "${Error} ${RedBG} 域名dns解析IP 与 本机IP 不匹配 是否继续安装？（y/n）${Font}" && read -r install
        case $install in
        [yY][eE][sS] | [yY])
            echo -e "${GreenBG} 继续安装 ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${RedBG} 安装终止 ${Font}"
            exit 2
            ;;
        esac
    fi
}

#===============================================================================#
#				ssl配置						#
#===============================================================================#
ssl_install() {
    if [[ "${ID}" == "centos" ]]; then
        ${INS} install socat nc -y
    else
        ${INS} install socat netcat -y
    fi
    judge "安装 SSL 证书生成脚本依赖"

    curl https://get.acme.sh | sh
    judge "安装 SSL 证书生成脚本"
}



#===============================================================================#
#					配置nginx				#
#===============================================================================#
nginx_config(){
    if [[ "${ID}" == "centos" ]]; then
	    mkdir mkdir /etc/nginx/sites-available && mkdir /etc/nginx/sites-enabled
	    #centos日后再补
 
    else
	    rm /etc/nginx/sites-enabled/default
	    cat > /etc/nginx/sites-available/${domain}<<EOF
server {
	listen 127.0.0.1:80 default_server;
	server_name $domain;
	location / {
		proxy_pass https://www.ietf.org;
	}
}

server {
    listen 127.0.0.1:80;

    server_name ${domain_ip};

    return 301 https://$domain$request_uri;
}

server {
    listen 0.0.0.0:80;
    listen [::]:80;

    server_name _;

    location / {
        return 301 https://$host$request_uri;
    }

    location /.well-known/acme-challenge {
       root /var/www/acme-challenge;
    }
}
EOF
	ln -s /etc/nginx/sites-available/$(domain) /etc/nginx/sites-enabled/
	systemctl restart nginx

    fi
    
}

#===============================================================================#
#					配置证书				#
#===============================================================================#
acme_config() {
	mkdir -p /etc/letsencrypt/live #创建证书文件夹
	usermod -G certusers www-data
	mkdir -p  /var/www/acme-challenge
	curl  https://get.acme.sh | sh #安装acme
	if "$HOME"/.acme.sh/acme.sh --issue -d "$domain" -w /var/www/acme-challenge;then
		echo -e "${OK} ${GreenBG} SSL证书申请成功 ${Font}"
		sleep 2
	else
		echo -e "${Error} ${RedBG} SSL证书申请失败 ${Font}"
		exit 1
	fi


	if "$HOME"/.acme.sh/acme.sh --install-cert -d $domain --key-file /etc/letsencrypt/live/private.key --fullchain-file /etc/letsencrypt/live/certificate.crt;then
		echo -e "${OK} ${GreenBG} SSL证书安装成功 ${Font}"
		sleep 2
	
	acme.sh  --upgrade  --auto-upgrade
	else 
		echo -e "${OK} ${RedBG} SSL证书安装失败 ${Font}"
		exit 1
	fi
}

#==============================================================================#
#				配置trojan	
#==============================================================================#
trojan_setup(){
    check_system
    is_root
    judge
    dependency_install
    domain_check
    ssl_install
    nginx_config
    acme_config
	bash -c "$(curl -fsSL https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"
	mv /usr/local/etc/trojan/config.json /usr/local/etc/trojan/config.json.bak
    cat > /usr/local/etc/trojan/config.json <<-EOF
 {
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        ${Trojan_Passwd}
    ],
    "log_level": 1,
    "ssl": {
        "cert": ${Cert_Path},
        "key": ${Key_Path},
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "alpn_port_override": {
            "h2": 81
        },
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": "",
        "key": "",
        "cert": "",
        "ca": ""
    }
}
 
EOF
cat > ${systempwd}trojan.service <<-EOF
[Unit]  
Description=trojan  
After=network.target network-online.target nss-lookup.target mysql.service mariadb.service mysqld.service
   
[Service]  
Type=simple  
ExecStart="/usr/local/bin/trojan" "/usr/local/etc/trojan/config.json"  
ExecReload=/bin/kill -HUP $MAINPID
LimitNOFILE=51200
Restart=on-failure
PrivateTmp=true  
   
[Install]  
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart trojan
echo "${Green}你的trojan配置如下：${Font}"
echo "${Green}服务器地址：${domain}${Font}"
echo "${Green}端口：443${Font}"
echo "${Green}密码：${Trojan_Passwd}${Font}"
echo "${Green}请选择：1.回到主菜单，2.退出安装程序${Font}"
read -p "请输入数字：" num
case $num in
1)
start_menu
;;
2)
exit 1
;;
*)
clear
echo "${Red}请输入数字${Font}"
sleep 1s 
start_menu
;;
esac
}

Update_Https(){
    echo "${Green}[请输入crontab -e命令，并在末尾输入0 0 1 * * killall -s SIGUSR1 trojan]${Font}"
}

BBR_config{
    bash -c 'echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf'
    bash -c 'echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf'
}

uninstall_trojan(){
    systemctl stop trojan
    systemctl disable trojan
    rm -f ${Systempwd}trojan.service
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        
        ${INS} remove -y nginx
    else [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        ${INS} autoremove -y nginx
    fi
    rm -rf /usr/local/etc/trojan*
    rm -rf /usr/share/nginx/html/*
    rm -rf /etc/nginx*

}
start_menu(){
    clear
    echo "${Green}此脚本为trojan一键安装脚本${Font}"
    echo =========================================
    echo "${GreenBG}1.一键安装trojan${Font}"
    echo "${GreenBG}2.开启BBR加速${Font}"
    echo "${GreenBG}3.设置证书自动更新${Font}"
    echo "${GreenBG}4.卸载trojan${Font}"
    echo "${GreenBG}5.退出安装程序${Font}"
    read -p "请输入你的选择" num
    case "$num" in 
    1)
    trojan_setup
    ;;
    2)
    BBR_config
    ;;
    3)
    Update_Https
    ;;
    4)
    uninstall_trojan
    ;;
    5)
    exit 1
    ;;
    esac

}