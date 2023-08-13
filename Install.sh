#!/bin/bash

# 定义颜色变量
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 开启 BBR
enable_bbr() {
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "开启 BBR..."
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo -e "${GREEN}BBR 已开启${NC}"
    else
        echo -e "${YELLOW}BBR 已经开启，跳过配置。${NC}"
    fi
}

# 检查是否存在文件夹，不存在则创建
check_and_create_folder() {
    local folder=$1
    if [ ! -d "$folder" ]; then
        mkdir -p "$folder"
        echo -e "${GREEN}创建 $folder 成功。${NC}"
    else
        echo -e "${YELLOW}$folder 已存在，跳过创建。${NC}"
    fi
}

# 检查是否存在文件，不存在则创建
check_and_create_file() {
    local file=$1
    if [ ! -f "$file" ]; then
        touch "$file"
        echo -e "${GREEN}创建 $file 成功。${NC}"
    else
        echo -e "${YELLOW}$file 已存在，跳过创建。${NC}"
    fi
}

# 选择安装方式
select_sing_box_install_option() {
    echo -e "${CYAN}请选择 sing-box 的安装方式：${NC}"
    echo -e "${CYAN}1. 自行编译安装${NC}"
    echo -e "${CYAN}2. 下载预编译版本${NC}"
}

# 安装 Go
install_go() {
    if ! command -v go &> /dev/null; then
         echo "下载并安装 Go..."
        local go_arch
        if [[ $(arch) == "x86_64" ]]; then
            go_arch="amd64"
        elif [[ $(arch) == "aarch64" ]]; then
            go_arch="arm64"
        else
            echo -e "${RED}不支持的架构: $(arch)${NC}"
            exit 1
        fi

        wget -c "https://go.dev/dl/go1.20.5.linux-$go_arch.tar.gz" -O - | tar -xz -C /usr/local
        echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile
        source /etc/profile

        echo -e "${GREEN}Go 已安装${NC}"
    else
        echo -e "${YELLOW}Go 已经安装，跳过安装步骤。${NC}"
    fi
}

#安装sing-box
compile_install_sing_box() {
    echo "编译安装 sing-box..."
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Go 未安装，请先安装 Go。${NC}"
        exit 1
    fi

    # 选择合适的模块版本
    sing_box_version=$(go list -m -versions github.com/sagernet/sing-box/cmd/sing-box | tail -1)

    go install -v -tags "with_dhcp@${sing_box_version},with_dhcp,with_wireguard@${sing_box_version},with_ech@${sing_box_version},with_utls@${sing_box_version},with_clash_api@${sing_box_version},with_v2ray_api@${sing_box_version},with_gvisor@${sing_box_version},with_lwip@${sing_box_version}" \
        github.com/sagernet/sing-box/cmd/sing-box@latest

    if [[ $? -eq 0 ]]; then
        cp ~/go/bin/sing-box /usr/local/bin/
        chmod +x /usr/local/bin/sing-box
        echo -e "${GREEN}sing-box 编译安装成功${NC}"
    else
        echo -e "${RED}sing-box 编译安装失败${NC}"
        exit 1
    fi
}

# 下载预编译版 sing-box
download_precompiled_sing_box() {
    if [[ $(arch) == "x86_64" ]]; then
        echo "下载并安装预编译的 sing-box (AMD 内核)..."
        wget -c "https://github.com/SagerNet/sing-box/releases/download/v1.3.0/sing-box-1.3.0-linux-amd64.tar.gz" -O - | tar -xz -C /usr/local/bin --strip-components=1
    elif [[ $(arch) == "aarch64" ]]; then
        echo "下载并安装预编译的 sing-box (ARM 内核)..."
        wget -c "https://github.com/SagerNet/sing-box/releases/download/v1.3.0/sing-box-1.3.0-linux-arm64.tar.gz" -O - | tar -xz -C /usr/local/bin --strip-components=1
    else
        echo -e "${RED}不支持的架构: $(arch)${NC}"
        exit 1
    fi

    chmod +x /usr/local/bin/sing-box
    echo -e "${GREEN}sing-box 安装成功${NC}"
}

# 检查防火墙配置
check_firewall_configuration() {
    if command -v ufw >/dev/null 2>&1; then
        echo "检查防火墙配置..."
        if ! ufw status | grep -q "Status: active"; then
            ufw enable
        fi

        if ! ufw status | grep -q " $listen_port"; then
            ufw allow "$listen_port"
        fi

        echo "防火墙配置已更新。"
    fi
}

# 配置 sing-box 开机自启服务
configure_sing_box_service() {
    echo "配置 sing-box 开机自启服务..."
    echo "[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
Restart=on-failure
RestartSec=1800s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target" | tee /etc/systemd/system/sing-box.service
}

# 生成随机用户名
generate_random_username() {
    local username=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)
    echo "$username"
}

# 配置 sing-box 配置文件
configure_sing_box_config_file() {
    local config_dir="/usr/local/etc/sing-box"
    local config_file="$config_dir/config.json"

    check_and_create_folder "$config_dir"
    check_and_create_file "$config_file"

    # 设置监听端口及用户名
    local username=$(generate_random_username)
    read -p "$(echo -e "${CYAN}请输入监听端口 (默认443):  ${NC}")" listen_port

    while true; do
        if [[ $listen_port =~ ^[1-9][0-9]{0,4}$ && $listen_port -le 65535 ]]; then
            echo -e "${GREEN}监听端口设置成功：$listen_port${NC}"
            break
        elif [[ -z $listen_port ]]; then
            listen_port=443
            echo -e "${GREEN}监听端口设置成功：$listen_port${NC}"
            break
        else
            echo -e "${RED}错误：监听端口范围必须在1-65535之间，请重新输入。${NC}"
            read -p "$(echo -e "${GREEN}请输入监听端口 (默认443): ${NC}")" listen_port
        fi
    done

    read -p "$(echo -e "${CYAN}请输入用户名 (默认随机生成): ${NC}")" new_username
    username=${new_username:-$username}

    echo -e "${GREEN}用户名: $username${NC}"

    # 生成 ShadowTLS 密码
    read -p "$(echo -e "${CYAN}请选择 Shadowsocks 加密方式：
1. 2022-blake3-chacha20-poly1305
2. 2022-blake3-aes-256-gcm
3. 2022-blake3-aes-128-gcm
请输入对应的数字 (默认1): ${NC}")" encryption_choice
    encryption_choice=${encryption_choice:-1}

    case $encryption_choice in
        1)
            ss_method="2022-blake3-chacha20-poly1305"
            shadowtls_password=$(openssl rand -base64 32)
            ss_password=$(openssl rand -base64 32)
            ;;
        2)
            ss_method="2022-blake3-aes-256-gcm"
            shadowtls_password=$(openssl rand -base64 32)
            ss_password=$(openssl rand -base64 32)
            ;;
        3)
            ss_method="2022-blake3-aes-128-gcm"
            shadowtls_password=$(openssl rand -base64 16)
            ss_password=$(openssl rand -base64 16)
            ;;
        *)
            echo -e "${RED}无效的选择，使用默认加密方式。${NC}"
            ss_method="2022-blake3-chacha20-poly1305"
            shadowtls_password=$(openssl rand -base64 32)
            ss_password=$(openssl rand -base64 32)
            ;;
    esac

    echo -e "${GREEN}加密方式: $ss_method${NC}"

    read -p "$(echo -e "${CYAN}请输入握手服务器地址 (默认www.apple.com): ${NC}")" handshake_server
    handshake_server=${handshake_server:-www.apple.com}

    # 验证握手服务器是否支持TLS 1.3
    echo "正在验证握手服务器支持的TLS版本..."

    while true; do
        openssl_output=$(timeout 20s openssl s_client -connect "$handshake_server:443" -tls1_3 2>&1)

        if [[ $openssl_output == *"Protocol  : TLSv1.3"* ]]; then
            echo -e "${GREEN}握手服务器支持TLS 1.3。${NC}"
            break
        else
            echo -e "${RED}错误：握手服务器不支持TLS 1.3，请重新输入握手服务器地址。${NC}"
            read -p "$(echo -e "${GREEN}请输入握手服务器地址 (默认www.apple.com): ${NC}")" handshake_server
            handshake_server=${handshake_server:-www.apple.com}
            echo "正在验证握手服务器支持的TLS版本..."
        fi
    done

    # 写入配置文件
    echo "{
  \"inbounds\": [
    {
      \"type\": \"shadowtls\",
      \"tag\": \"st-in\",
      \"listen\": \"::\",
      \"listen_port\": $listen_port,
      \"version\": 3,
      \"users\": [
        {
          \"name\": \"$username\",
          \"password\": \"$shadowtls_password\"
        }
      ],
      \"handshake\": {
        \"server\": \"$handshake_server\",
        \"server_port\": 443
      },
      \"strict_mode\": true,
      \"detour\": \"ss-in\"
    },
    {
      \"type\": \"shadowsocks\",
      \"tag\": \"ss-in\",
      \"listen\": \"127.0.0.1\",
      \"network\": \"tcp\",
      \"method\": \"$ss_method\",
      \"password\": \"$ss_password\"
    }
  ],
  \"outbounds\": [
    {
      \"type\": \"direct\",
      \"tag\": \"direct\"
    },
    {
      \"type\": \"block\",
      \"tag\": \"block\"
    }
  ]
}" > "$config_file"

    echo "配置文件 $config_file 创建成功。"
}

# 显示 sing-box 配置信息
display_sing_box_config() {
    local config_file="/usr/local/etc/sing-box/config.json"

    echo -e "${CYAN}ShadowTLS 节点配置信息：${NC}"
    echo -e "${CYAN}用户名: $(jq -r '.inbounds[0].users[0].name' $config_file)${NC}"
    echo -e "${CYAN}监听端口: $(jq -r '.inbounds[0].listen_port' $config_file)${NC}"
    echo -e "${CYAN}握手服务器地址: $(jq -r '.inbounds[0].handshake.server' $config_file)${NC}"
    echo -e "${CYAN}ShadowTLS 密码: $(jq -r '.inbounds[0].users[0].password' $config_file)${NC}"
    echo -e "${CYAN}Shadowsocks 密码: $(jq -r '.inbounds[1].password' $config_file)${NC}"
}

# 安装 sing-box
install_sing_box() {
    echo "开始安装 sing-box..."

    # 选择安装方式
    select_sing_box_install_option

    local install_option
    read -p "$(echo -e "${CYAN}请选择 [1-2]: ${NC}")" install_option

    case $install_option in
        1)
            install_go
            compile_install_sing_box
            ;;
        2)
            download_precompiled_sing_box
            ;;
        *)
            echo -e "${RED}无效的选择，请重新输入。${NC}"
            install_sing_box
            ;;
    esac

    echo -e "${GREEN}sing-box 安装完成。${NC}"

    configure_sing_box
    check_firewall_configuration
    start_sing_box_service
}

# 配置 sing-box
configure_sing_box() {
    echo "开始配置 sing-box..."

    echo "配置 sing-box 服务..."
    configure_sing_box_service > /dev/null

    echo "配置 sing-box 配置文件..."
    configure_sing_box_config_file 

    echo -e "${GREEN}sing-box 配置完成。${NC}"
}
  
# 启动 sing-box 服务
start_sing_box_service() {
    echo "启动 sing-box 服务..."
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}sing-box 服务已启动。${NC}"
    else
        echo -e "${RED}启动 sing-box 服务失败。${NC}"
    fi
    
    # 显示 sing-box 配置信息
    display_sing_box_config
}

# 主菜单
main_menu() {
    echo -e "${CYAN}欢迎使用 sing-box 安装脚本！${NC}"
    echo -e "${CYAN}请选择要执行的操作：${NC}"
    echo -e "${CYAN}1. 安装 sing-box 服务${NC}"
    echo -e "${CYAN}2. 停止 sing-box 服务${NC}"
    echo -e "${CYAN}3. 重启 sing-box 服务${NC}"
    echo -e "${CYAN}4. 查看 sing-box 日志${NC}"
    echo -e "${CYAN}5. 卸载 sing-box${NC}"
    echo -e "${CYAN}6. 退出脚本${NC}"

    local choice
    read -p "$(echo -e "${CYAN}请选择 [1-6]: ${NC}")" choice

    case $choice in
        1)
            install_sing_box
            ;;
        2)
            stop_sing_box_service
            ;;
        3)
            restart_sing_box_service
            ;;
        4)
            view_sing_box_log
            ;;
        5)
            uninstall_sing_box
            ;;
        6)
            echo -e "${GREEN}感谢使用 sing-box 安装脚本！再见！${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}无效的选择，请重新输入。${NC}"
            main_menu
            ;;
    esac
}

# 停止 sing-box 服务
stop_sing_box_service() {
    echo "停止 sing-box 服务..."
    systemctl stop sing-box

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}sing-box 服务已停止。${NC}"
    else
        echo -e "${RED}停止 sing-box 服务失败。${NC}"
    fi
}

# 重启 sing-box 服务
restart_sing_box_service() {
    echo "重启 sing-box 服务..."
    systemctl restart sing-box

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}sing-box 服务已重启。${NC}"
    else
        echo -e "${RED}重启 sing-box 服务失败。${NC}"
    fi
}

# 查看 sing-box 服务日志
view_sing_box_log() {
    echo "正在查看 sing-box 服务日志..."
    journalctl -u sing-box -f
}

# 卸载 sing-box
uninstall_sing_box() {
    echo "开始卸载 sing-box..."

    stop_sing_box_service

    # 删除文件和文件夹
    echo "删除文件和文件夹..."
    rm -rf /usr/local/bin/sing-box
    rm -rf /usr/local/etc/sing-box
    rm -rf /etc/systemd/system/sing-box.service

    echo -e "${GREEN}sing-box 卸载完成。${NC}"
}

main_menu
