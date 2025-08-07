#!/bin/bash

# Ambil tanggal dari server Google
dateFromServer=$(curl -s --insecure -I https://google.com | grep -i ^Date: | sed 's/Date: //')
biji=$(date -d "$dateFromServer" +"%Y-%m-%d")

# Warna teks
red() { echo -e "\\033[32;1m${*}\\033[0m"; }

# Progress bar function
fun_bar() {
    CMD[0]="$1"
    CMD[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm $HOME/fim
        ${CMD[0]} -y >/dev/null 2>&1
        ${CMD[1]} -y >/dev/null 2>&1
        touch $HOME/fim
    ) >/dev/null 2>&1 &

    tput civis
    echo -ne "  \033[0;33mPlease Wait Loading \033[1;37m- \033[0;33m["
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "\033[0;32m#"
            sleep 0.1
        done
        [[ -e $HOME/fim ]] && rm $HOME/fim && break
        echo -e "\033[0;33m]"
        sleep 1
        tput cuu1
        tput dl1
        echo -ne "  \033[0;33mPlease Wait Loading \033[1;37m- \033[0;33m["
    done
    echo -e "\033[0;33m]\033[1;37m -\033[1;32m OK!\033[0m"
    tput cnorm
}

# Fungsi update menu
res1() {
    wget -q https://raw.githubusercontent.com/kemetstore/vip/main/limit/menu.zip
    unzip -o menu.zip >/dev/null 2>&1
    chmod +x menu/*
    mv menu/* /usr/local/sbin/
    rm -rf menu menu.zip update.sh
}

# Reload netfilter jika tersedia
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent reload >/dev/null 2>&1
    systemctl restart netfilter-persistent >/dev/null 2>&1
fi

# Tampilan
clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " \e[1;97;101m          UPDATE SCRIPT    \e[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
echo -e "  \033[1;91m Update script service...\033[0m"
fun_bar 'res1'
echo -e ""
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -n 1 -s -r -p "Press [ Enter ] to return to menu"
menu
