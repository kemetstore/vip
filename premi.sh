#!/bin/bash

# === Update & Install Tools Dasar ===
apt update -y && apt upgrade -y
apt install -y lolcat wondershaper curl wget jq

# === WARNA ===
GREEN="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
GRAY="\e[1;30m"
NC='\e[0m'
OK="${GREEN}[OK]${NC}"
ERROR="${RED}[ERROR]${NC}"

# === BACA INFO ISP DAN KOTA (fallback kalau file nggak ada) ===
ISP=$(cat /etc/xray/isp 2>/dev/null || echo "Unknown")
CITY=$(cat /etc/xray/city 2>/dev/null || echo "Unknown")

# === DAPATKAN IP PUBLIK ===
ipsaya=$(curl -s https://ipinfo.io/ip)

# === TAMPILKAN INFO AWAL ===
clear
echo -e "${YELLOW}-----------------------------------------------${NC}"
echo -e "${GREEN}           KEMET JS STORE INITIAL SETUP${NC}"
echo -e "${YELLOW}-----------------------------------------------${NC}"
echo -e "${BLUE}IP Address  :${NC} $ipsaya"
echo -e "${BLUE}ISP         :${NC} $ISP"
echo -e "${BLUE}City        :${NC} $CITY"
echo -e "${YELLOW}-----------------------------------------------${NC}"
sleep 2

# === BANNER ===
clear
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e "   Welcome to ${GREEN}KEMET JS STORE VPN Setup${NC} ${YELLOW}(Stable Edition)${NC}"
echo -e "   This script will quickly install a VPN server on your system."
echo -e "   Author  : ${GREEN}Kemet Premium®${NC} (${BLUE}kemetjs.github.io${NC})"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 2

# === CEK ARSITEKTUR OS ===
arch=$(uname -m)
echo -e "${OK} Detected Architecture: ${GREEN}$arch${NC}"

if [[ "$arch" != "x86_64" ]]; then
    echo -e "${YELLOW}[WARNING]${NC} Non-x86_64 architecture detected. Pastikan script kompatibel."
fi

# === CEK SISTEM OPERASI ===
os_id=$(grep -w ID /etc/os-release | cut -d= -f2 | tr -d '"')
os_name=$(grep -w PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')

echo -e "${OK} Detected OS: ${GREEN}$os_name${NC}"

if [[ "$os_id" != "ubuntu" && "$os_id" != "debian" ]]; then
    echo -e "${YELLOW}[WARNING]${NC} Non-Ubuntu/Debian system detected. Pastikan semua fitur kompatibel."
fi

# === VALIDASI MANUAL (ENTER UNTUK LANJUT) ===
echo ""
read -p "$(echo -e "Press ${GRAY}[ ${NC}${GREEN}Enter${NC} ${GRAY}]${NC} to start the installation...") "
echo ""

# === CEK AKSES ROOT ===
if [ "${EUID}" -ne 0 ]; then
    echo -e "${ERROR} You need to run this script as root."
    exit 1
fi

# === CEK VIRTUALISASI ===
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo -e "${ERROR} OpenVZ virtualization is not supported."
    exit 1
fi

# === IZIN SCRIPT ===
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "${GREEN}Loading authorization data...${NC}"
sleep 1
clear


# Ambil informasi user dari izin database
username=$(curl -s https://raw.githubusercontent.com/kemetstore/izinsc/main/ip | grep $MYIP | awk '{print $2}')
exp_date=$(curl -s https://raw.githubusercontent.com/kemetstore/izinsc/main/ip | grep $MYIP | awk '{print $3}')
geo_exp=$(curl -s https://raw.githubusercontent.com/kemetstore/izinsc/main/ip | grep $MYIP | awk '{print $4}')

# Simpan ke file lokal
echo "$username" > /usr/bin/user
echo "$exp_date" > /usr/bin/e

# Tampilkan detail
today=$(date +%Y-%m-%d)
if [[ -n "$exp_date" ]]; then
    d1=$(date -d "$exp_date" +%s)
    d2=$(date -d "$today" +%s)
    cert_days=$(( (d1 - d2) / 86400 ))
else
    cert_days="Unknown"
fi

# Tampilkan info
echo -e "${green}Authorization Success${NC}"
echo -e "${green}Username     :${NC} $username"
echo -e "${green}IP Address   :${NC} $MYIP"
echo -e "${green}Expiry Date  :${NC} $exp_date"
echo -e "${green}Valid for    :${NC} $cert_days days"
echo ""

# ========================
# STATUS EXPIRED / AKTIF
# ========================
Info="(${green}Active${NC})"
Error="(${red}Expired${NC})"

# Ambil data expired untuk Geo/IP
today=$(date -d "0 days" +"%Y-%m-%d")
if [[ "$today" < "$geo_exp" ]]; then
    sts="$Info"
else
    sts="$Error"
fi

echo -e "${green}Checking License Status...${NC}"
sleep 2
clear

# Set REPO URL
REPO="https://raw.githubusercontent.com/kemetstore/kemetvip/main/"

### Timer Awal
start=$(date +%s)

# === Konversi Detik ke Format Waktu ===
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minutes $((${1} % 60)) seconds"
}

# === Fungsi Status ===
function print_ok() {
    echo -e "${OK} ${BLUE}$1${NC}"
}

function print_install() {
    sleep 1
    echo -e "${green}===============================${NC}"
    echo -e "${YELLOW}# $1${NC}"
    echo -e "${green}===============================${NC}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${NC}"
}
function print_success() {
    if [[ $? -eq 0 ]]; then
        echo -e "${green}===============================${NC}"
        echo -e "${GREEN}# $1 berhasil dipasang${NC}"
        echo -e "${green}===============================${NC}"
        sleep 2
    fi
}
# === Fungsi Cek Root ===
function is_root() {
    if [[ $UID -eq 0 ]]; then
        print_ok "Root user terdeteksi. Melanjutkan instalasi..."
    else
        print_error "User saat ini bukan root! Jalankan script sebagai root."
        exit 1
    fi
}
# Buat direktori xray
print_install "Membuat direktori xray"

# Direktori utama
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain

# Log Xray
mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
chmod 755 /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log

# Direktori library tambahan
mkdir -p /var/lib/kyt >/dev/null 2>&1


# Ambil Informasi RAM
mem_total=0
mem_used=0
while IFS=":" read -r key value; do
    case $key in
        "MemTotal") mem_total=${value//[!0-9]/} ;;
        "Shmem") ((mem_used+=${value//[!0-9]/})) ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable") 
            ((mem_used-=${value//[!0-9]/})) ;;
    esac
done < /proc/meminfo

Ram_Usage=$((mem_used / 1024))
Ram_Total=$((mem_total / 1024))

# Informasi sistem
tanggal=$(date +"%d-%m-%Y - %X")
OS_Name=$(grep -w PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Kernel=$(uname -r)
Arch=$(uname -m)
Public_IP=$(curl -s https://ipinfo.io/ip)

export tanggal
export OS_Name
export Kernel
export Arch
export Public_IP

# Fungsi Setup Awal Sistem
function first_setup() {
    print_install "Melakukan setup awal sistem"
    timedatectl set-timezone Asia/Jakarta

    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 

    apt update -y
    apt install nginx iptables-persistent -y
}

# Update and remove packages
function base_package2() {
clear
########
print_install "Menginstall Packet Yang Dibutuhkan"
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt install sudo -y
sudo apt-get clean all
sudo apt-get autoremove -y
sudo apt-get install -y debconf-utils
sudo apt-get remove --purge exim4 -y
sudo apt-get remove --purge ufw firewalld -y
sudo apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

function ins_package() {
sudo apt install $1
}

ins_package "zip unzip p7zip-full bzip2 gzip"
ins_package "pwgen"
ins_package "bash-completion"
ins_package "speedtest-cli"
ins_package "vnstat"
ins_package "make"
ins_package "bc"
ins_package "rsyslog"
ins_package "sed"
ins_package "gcc"
ins_package "g++"
ins_package "python python3"
ins_package "htop"
ins_package "lsof"
ins_package "tar"
ins_package "wget curl"
ins_package "python3-pip"
ins_package "libc6"
ins_package "util-linux build-essential"
ins_package "bsd-mailx"
ins_package "iptables"
ins_package "iptables-persistent"
ins_package "netfilter-persistent"
ins_package "net-tools"
ins_package "openssl"
ins_package "shc"
ins_package "cmake"
ins_package "git"
ins_package "screen"
ins_package "socat"
ins_package "xz-utlis"
ins_package "apt-transport-https"
ins_package "bash-completion"
ins_package "ntpdate"
ins_package "jq"
ins_package "openvpn"
ins_package "easy-rsa"
ins_package "chrony"

systemctl enable chronyd
systemctl restart chronyd
systemctl enable chrony
systemctl restart chrony
chronyc sourcestats -v
chronyc tracking -v

print_success "Packet Yang Dibutuhkan"
}

function base_package() {
    clear
    sleep 1
    print_install "Menginstall Packet Yang Dibutuhkan"
    sudo apt update -y
    sudo apt install sudo -y
    sudo apt-get clean all
    sudo apt install -y debconf-utils
    sudo apt install p7zip-full -y
    sudo apt-get remove --purge ufw firewalld -y
    sudo apt-get remove --purge exim4 -y
    sudo apt-get autoremove -y
    sudo apt install -y --no-install-recommends software-properties-common
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y install iptables iptables-persistent netfilter-persistent libxml-parser-perl squid screen curl jq bzip2 gzip coreutils rsyslog zip unzip net-tools sed bc apt-transport-https build-essential dirmngr libxml-parser-perl lsof openvpn easy-rsa fail2ban tmux squid dropbear socat cron bash-completion ntpdate xz-utils apt-transport-https chrony pkg-config bison make git speedtest-cli p7zip-full zlib1g-dev python-is-python3 python3-pip shc build-essential nodejs nginx php php-fpm php-cli php-mysql p7zip-full squid libcurl4-openssl-dev

    # remove unnecessary files
    sudo apt-get autoclean -y >/dev/null 2>&1
    sudo apt-get -y --purge remove unscd >/dev/null 2>&1
    sudo apt-get -y --purge remove samba* >/dev/null 2>&1
    sudo apt-get -y --purge remove apache2* >/dev/null 2>&1
    sudo apt-get -y --purge remove bind9* >/dev/null 2>&1
    sudo apt-get -y remove sendmail* >/dev/null 2>&1
    sudo apt autoremove -y >/dev/null 2>&1
    print_success "Packet Yang Dibutuhkan"
}
clear
# Fungsi input domain
function pasang_domain() {
    # Definisi warna (jika belum ada)
    red='\e[31m'
    green='\e[32m'
    yellow='\e[33m'
    nc='\e[0m'

    clear
    echo -e "    ----------------------------------"
    echo -e "   |\e[1;32m Please Select a Domain Type Below \e[0m|"
    echo -e "    ----------------------------------"
    echo -e "     \e[1;32m1)\e[0m Your Domain"
    echo -e "     \e[1;32m2)\e[0m Random Domain (Belum Tersedia)"
    echo -e "   ------------------------------------"
    read -p "   Please select 1 or 2 (default: 2) : " host
    echo ""

    # Jika tidak input, default ke 2
    if [[ -z "$host" ]]; then
        host=2
    fi

    if [[ "$host" == "1" ]]; then
        clear
        echo -e "   \e[1;36m===============================$nc"
        echo -e "   \e[1;32m      GANTI DOMAIN MANUAL $nc"
        echo -e "   \e[1;36m===============================$nc"
        echo ""
        read -p "   Masukkan Domain Anda : " host1

        if [[ -z "$host1" ]]; then
            echo -e "\n   ${red}Domain tidak boleh kosong!${nc}"
            sleep 2
            pasang_domain
            return
        fi

        echo "$host1" > /etc/xray/domain
        echo "KEMET JS STORE" > /etc/xray/username
        echo -e "\n   ${green}Domain berhasil disimpan: $host1${nc}"
        sleep 2

    elif [[ "$host" == "2" ]]; then
        echo -e "${yellow}Fitur Random Domain belum tersedia.${nc}"
        sleep 2
        pasang_domain
        return
    else
        echo -e "${yellow}Input tidak valid, coba lagi.${nc}"
        sleep 1
        pasang_domain
        return
    fi
}
clear
# Pasang SSL
function install_ssl() {
    print_install "Memasang SSL Pada Domain"

    domain=$(cat /etc/xray/domain)

    # Bersihkan sertifikat lama
    rm -f /etc/xray/xray.key /etc/xray/xray.crt
    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    # Stop proses yang menggunakan port 80
    if lsof -t -i:80 >/dev/null 2>&1; then
        pid_port_80=$(lsof -t -i:80)
        echo "[INFO] Menghentikan proses di port 80 (PID: $pid_port_80)"
        kill -9 "$pid_port_80"
    fi

    # Stop nginx kalau aktif
    systemctl stop nginx >/dev/null 2>&1

    # Download acme.sh
    curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh

    # Upgrade & set default ke Let's Encrypt
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # Issue sertifikat
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256

    # Install sertifikat
    ~/.acme.sh/acme.sh --installcert -d "$domain" \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key --ecc

    # Set permission aman
    chmod 600 /etc/xray/xray.key
    chmod 644 /etc/xray/xray.crt

    print_success "✅ SSL Certificate berhasil dipasang untuk domain: $domain"
}
function make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/kyt/limit/vmess/ip
    mkdir -p /etc/kyt/limit/vless/ip
    mkdir -p /etc/kyt/limit/trojan/ip
    mkdir -p /etc/kyt/limit/ssh/ip
    mkdir -p /etc/limit/vmess
    mkdir -p /etc/limit/vless
    mkdir -p /etc/limit/trojan
    mkdir -p /etc/limit/ssh
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
    echo "& plughin Account" >>/etc/vmess/.vmess.db
    echo "& plughin Account" >>/etc/vless/.vless.db
    echo "& plughin Account" >>/etc/trojan/.trojan.db
    echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >>/etc/ssh/.ssh.db
    }
# Instalasi Xray Core
function install_xray() {
    clear
    print_install "Memasang Core Xray v1.8.1 - KEMET JS STORE"

    # Buat direktori socket jika belum ada
    domainSock_dir="/run/xray"
    if [[ ! -d "$domainSock_dir" ]]; then
        mkdir -p "$domainSock_dir"
        chown www-data:www-data "$domainSock_dir"
    fi

    # Install Xray Core 1.8.1
    if ! bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.1; then
        print_error "Gagal menginstall Xray Core"
        exit 1
    fi

    # Ambil konfigurasi dasar Xray & service
    echo -e "[INFO] Mengambil konfigurasi Xray dan Service..."
    wget -q -O /etc/xray/config.json "https://raw.githubusercontent.com/kipasu/nginx/master/config.json" || {
        print_error "Gagal download config.json"
        exit 1
    }
    wget -q -O /etc/systemd/system/runn.service "${REPO}Fls/runn.service" || {
        print_error "Gagal download runn.service"
        exit 1
    }

    # Baca domain & IP
    domain=$(cat /etc/xray/domain 2>/dev/null)
    IPVPS=$(cat /etc/xray/ipvps 2>/dev/null)

    print_success "Xray Core v1.8.1 berhasil dipasang"

    # Siapkan NGINX
    print_install "Menyiapkan Konfigurasi Paket NGINX"
    curl -s ipinfo.io/city > /etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 > /etc/xray/isp

    # Ambil konfigurasi nginx
    wget -q -O /etc/nginx/conf.d/xray.conf "https://raw.githubusercontent.com/kipasu/nginx/master/server.conf" || {
        print_error "Gagal download xray.conf"
        exit 1
    }
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl -s "${REPO}Cfg/nginx.conf" -o /etc/nginx/nginx.conf

    # Set permission
    chmod +x /etc/systemd/system/runn.service

    # Buat ulang service Xray manual
    rm -rf /etc/systemd/system/xray.service.d
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    # Reload dan enable service
    systemctl daemon-reexec
    systemctl daemon-reload
    systemctl enable xray
    systemctl enable runn.service

    print_success "Konfigurasi Xray & NGINX selesai dan aktif"
}

function ssh() {
    clear
    print_install "Memasang Password SSH"

    # Download konfigurasi password
    if ! wget -q -O /etc/pam.d/common-password "${REPO}Fls/password"; then
        print_error "Gagal download file password"
        exit 1
    fi
    chmod +x /etc/pam.d/common-password

    # Konfigurasi keyboard secara non-interaktif
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

    # Pindah ke direktori root
    cd
}

function setup_rc_local() {
    print_install "Setup rc.local + Disable IPv6 + Timezone + Locale"

    # Buat file service rc-local
    cat > /etc/systemd/system/rc-local.service <<-EOF
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF

    # Buat file rc.local
    cat > /etc/rc.local <<-EOF
#!/bin/sh -e
# rc.local startup
# KEMET JS STORE Autostart Script
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
exit 0
EOF

    chmod +x /etc/rc.local

    # Enable service
    systemctl enable rc-local.service >/dev/null 2>&1
    systemctl start rc-local.service

    # Set Timezone Asia/Jakarta (GMT +7)
    ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # Locale fix untuk SSH agar tidak error saat remote
    sed -i 's/^AcceptEnv/#AcceptEnv/' /etc/ssh/sshd_config

    print_success "Konfigurasi rc.local, timezone, dan IPv6"
}

function udp_mini() {
    clear
    print_install "Memasang Service Limit Quota & Multi IP"

    # === Unduh file service ===
    wget -q -O /etc/systemd/system/limitvmess.service "${REPO}Fls/limitvmess.service"
    wget -q -O /etc/systemd/system/limitvless.service "${REPO}Fls/limitvless.service"
    wget -q -O /etc/systemd/system/limittrojan.service "${REPO}Fls/limittrojan.service"
    wget -q -O /etc/systemd/system/limitshadowsocks.service "${REPO}Fls/limitshadowsocks.service"

    chmod +x /etc/systemd/system/limit*.service

    # === Unduh script limit traffic ===
    wget -q -O /etc/xray/limit.vmess "${REPO}Fls/vmess"
    wget -q -O /etc/xray/limit.vless "${REPO}Fls/vless"
    wget -q -O /etc/xray/limit.trojan "${REPO}Fls/trojan"
    wget -q -O /etc/xray/limit.shadowsocks "${REPO}Fls/shadowsocks"

    chmod +x /etc/xray/limit.*

    # === Reload dan aktifkan semua service ===
    systemctl daemon-reload
    systemctl enable --now limitvmess limitvless limittrojan limitshadowsocks

    # === Limit-IP Master Script ===
    wget -q -O /usr/bin/limit-ip "${REPO}Fls/limit-ip"
    chmod +x /usr/bin/limit-ip
    sed -i 's/\r//' /usr/bin/limit-ip  # Hapus karakter CR dari Windows

    # === Buat service untuk IP limit per protokol ===
    for proto in vmip vlip trip; do
        cat > /etc/systemd/system/${proto}.service <<-EOF
[Unit]
Description=Limit IP Service - $proto
After=network.target

[Service]
ExecStart=/usr/bin/limit-ip ${proto}
Restart=always
WorkingDirectory=/root

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable --now ${proto}
    done

    print_success "Semua service limit quota & IP berhasil diaktifkan"
}
function service_vmess_udp() {
    print_install "Memasang UDP-Mini (Service untuk VMESS)"

    # Buat direktori binary
    mkdir -p /usr/local/kyt/

    # Download binary UDP Mini
    wget -q -O /usr/local/kyt/udp-mini "${REPO}Fls/udp-mini"
    chmod +x /usr/local/kyt/udp-mini

    # Download systemd service file
    for i in 1 2 3; do
        wget -q -O "/etc/systemd/system/udp-mini-${i}.service" "${REPO}Fls/udp-mini-${i}.service"
    done

    # Enable dan jalankan servicenya
    systemctl daemon-reload
    systemctl enable --now udp-mini-{1,2,3}

    print_success "UDP-Mini & Limit Quota Service aktif untuk VMESS"
}
function ssh_slow(){
    clear
    print_install "Memasang modul SlowDNS Server"

    wget -q -O /tmp/nameserver "${REPO}Fls/nameserver"
    chmod +x /tmp/nameserver
    bash /tmp/nameserver

    print_success "SlowDNS"
}


clear
function ins_SSHD(){
    clear
    print_install "Memasang SSHD"

    wget -q -O /etc/ssh/sshd_config "${REPO}Fls/sshd"
    chmod 600 /etc/ssh/sshd_config

    systemctl restart ssh
    systemctl status ssh --no-pager

    print_success "SSHD"
}
clear
function ins_dropbear(){
    clear
    print_install "Menginstall Dropbear"

    apt-get install -y dropbear
    dropbearkey -t dss -f /etc/dropbear/dropbear_dss_host_key
    chmod 600 /etc/dropbear/dropbear_dss_host_key

    wget -q -O /etc/default/dropbear "${REPO}Cfg/dropbear.conf"

    echo "/bin/false" >> /etc/shells
    echo "/usr/sbin/nologin" >> /etc/shells

    systemctl restart ssh
    systemctl restart dropbear

    print_success "Dropbear"
}
clear
function ins_vnstat(){
    clear
    print_install "Menginstall Vnstat"

    apt -y install vnstat libsqlite3-dev > /dev/null 2>&1

    # Kompilasi versi terbaru (opsional)
    wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar -xzf vnstat-2.6.tar.gz
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc && make && make install
    cd ~
    rm -rf vnstat-2.6 vnstat-2.6.tar.gz

    vnstat -u -i eth0  # Default, nanti bisa diganti
    sed -i 's/Interface "eth0"/Interface "'$NET'"/g' /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R

    systemctl enable --now vnstat

    print_success "Vnstat"
}
function ins_openvpn(){
    clear
    print_install "Menginstall OpenVPN"

    wget -q ${REPO}Vpn/openvpn
    chmod +x openvpn
    ./openvpn

    systemctl restart openvpn
    print_success "OpenVPN"
}
function ins_backup(){
    clear
    print_install "Memasang Backup Server"

    apt install -y rclone git

    mkdir -p /root/.config/rclone
    wget -q -O /root/.config/rclone/rclone.conf "${REPO}Cfg/rclone.conf"

    # Install Wondershaper
    git clone https://github.com/magnific0/wondershaper.git /tmp/wondershaper
    cd /tmp/wondershaper
    make install
    cd ~
    rm -rf /tmp/wondershaper

    touch /home/limit
    wget -q -O /etc/ipserver "${REPO}Fls/ipserver" && bash /etc/ipserver

    print_success "Backup Server"
}
function ins_swab(){
    clear
    print_install "Memasang Swap 1G + Gotop + BBR"

    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v([^"]+)".*/\1/' | head -n1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v${gotop_latest}_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1

    # Buat Swap
    dd if=/dev/zero of=/swapfile bs=1M count=1024
    mkswap /swapfile
    chmod 600 /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab

    # Sync waktu
    apt install -y chrony
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v

    # Pasang BBR
    wget -q ${REPO}Fls/bbr.sh
    bash bbr.sh

    print_success "Swap 1G & BBR"
}
function ins_Fail2ban(){
    clear
    print_install "Menginstall Fail2Ban & Anti Torrent"

    apt -y install fail2ban

    systemctl restart fail2ban
    systemctl status fail2ban --no-pager

    # Anti torrent banner
    echo "Banner /etc/banner.txt" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear
    wget -q -O /etc/banner.txt "${REPO}banner.txt"

    print_success "Fail2Ban"
}
function ins_epro(){
    clear
    print_install "Memasang ePro WebSocket Proxy"

    wget -q -O /usr/bin/ws "${REPO}Fls/ws"
    wget -q -O /usr/bin/tun.conf "${REPO}Cfg/tun.conf"
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf

    cat <<EOF > /etc/systemd/system/ws.service
[Unit]
Description=WebSocket Proxy
After=network.target

[Service]
ExecStart=/usr/bin/ws -f /usr/bin/tun.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ws
    systemctl restart ws

    # Block torrent traffic
    for rule in "get_peers" "announce_peer" "find_node" "BitTorrent" "BitTorrent protocol" \
                "peer_id=" ".torrent" "announce.php?passkey=" "torrent" "announce" "info_hash"; do
        iptables -A FORWARD -m string --string "$rule" --algo bm -j DROP
    done

    iptables-save > /etc/iptables.up.rules
    iptables-restore < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload

    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1

    print_success "ePro WebSocket Proxy"
}
function ins_restart(){
    clear
    print_install "Restart Semua Layanan"

    systemctl daemon-reload
    systemctl enable --now {nginx,xray,rc-local,dropbear,openvpn,cron,netfilter-persistent,ws,fail2ban}

    for svc in nginx openvpn ssh dropbear fail2ban vnstat cron; do
        systemctl restart $svc
    done

    history -c
    echo "unset HISTFILE" >> /etc/profile

    # Clean junk
    rm -f /root/{openvpn,key.pem,cert.pem}

    print_success "Semua Layanan Dinyalakan Ulang"
}
#Instal Menu
function menu(){
    clear
    print_install "Mengunduh & Memasang Menu CLI"

    mkdir -p /cache
    cd /cache
    wget -q ${REPO}Cdy/menu.zip

    unzip menu.zip -d menu/
    chmod +x menu/*
    mv menu/* /usr/sbin

    cd
    rm -rf /cache

    print_success "Menu CLI Terpasang"
}
# Membaut Default Menu 
function profile(){
clear
cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "\$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
welcome
EOF

# Cron job untuk clear log
cat >/etc/cron.d/log_clear <<EOF
8 0 * * * root /usr/local/bin/log_clear
EOF

cat >/usr/local/bin/log_clear <<EOF
#!/bin/bash
tanggal=\$(date +"%m-%d-%Y")
waktu=\$(date +"%T")
echo "Successfully cleared log at \$tanggal \$waktu." >> /root/log-clear.txt
systemctl restart udp-custom.service
EOF
chmod +x /usr/local/bin/log_clear

# Cron job untuk backup
cat >/etc/cron.d/daily_backup <<EOF
*/59 * * * * root /usr/local/bin/daily_backup
EOF

cat >/usr/local/bin/daily_backup <<EOF
#!/bin/bash
tanggal=\$(date +"%m-%d-%Y")
waktu=\$(date +"%T")
echo "Successfully backed up at \$tanggal \$waktu." >> /root/log-backup.txt
/usr/sbin/backup -r now
EOF
chmod +x /usr/local/bin/daily_backup

# Cron job untuk xp_sc
cat >/etc/cron.d/xp_sc <<EOF
5 0 * * * root /usr/local/bin/xp_sc
EOF

cat >/usr/local/bin/xp_sc <<EOF
#!/bin/bash
/usr/sbin/expsc -r now
EOF
chmod +x /usr/local/bin/xp_sc

# Cron untuk xp_all
cat >/etc/cron.d/xp_all <<EOF
2 0 * * * root /usr/sbin/xp
EOF

# Cron untuk logclean
cat >/etc/cron.d/logclean <<EOF
*/10 * * * * root /usr/sbin/clearlog
EOF

chmod 644 /root/.profile

# Reboot harian
cat >/etc/cron.d/daily_reboot <<EOF
5 0 * * * root /sbin/reboot
EOF

# Clear log nginx dan xray
echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" > /etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log" > /etc/cron.d/log.xray

# Aktifkan cron service
service cron restart

# Set waktu reboot
echo "5" > /home/daily_reboot

# Shell tambahan
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells

# Format waktu
AUTOREB=$(cat /home/daily_reboot)
SETT=11
if [[ $AUTOREB -gt $SETT ]]; then
    TIME_DATE="PM"
else
    TIME_DATE="AM"
fi

print_success "Menu Packet"
}
# Fingsi Install Script
function instal(){
    clear
    first_setup
    install_xray
    ssh_slow
    ins_SSHD
    ins_dropbear
    ins_vnstat
    ins_openvpn
    ins_backup
    ins_swab
    ins_Fail2ban
    ins_epro
    menu
    profile
    ins_restart
}

instal
echo ""
apt install openvpn -y
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain

# Set hostname
sudo hostnamectl set-hostname "$username"

# Tampilkan waktu instalasi
secs_to_human "$(($(date +%s) - ${start}))"

# Info akhir
echo -e "${green}Script berhasil diinstall.${NC}"
echo ""
read -p "$(echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} untuk reboot") "
reboot

exit 0
