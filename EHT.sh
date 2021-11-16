#!/bin/bash
###############################################################################
# Descricao: Script EHT - Gray Box
#------------------------------------------------------------------------------
# Usabilidade:
# - ./EHT.sh
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# ID                    Date                    version
# Roberto.Lima  		2021.11.11              0.1
# Renato.Borbolla  		2021.11.12              0.2
#------------------------------------------------------------------------------
###############################################################################
#set -x       #Descommentar essa linha para ver em modo debug o script
###############################################################################
clear
#Variaveis globais
#------------------------------------------
OFF=/dev/null
SYS=/etc/sysctl.conf
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
NC='\033[0m'
OK=`echo -e "["${NC}${GREEN}✔${NC}${WHITE}"]"`
FAIL=`echo -e "["${NC}${RED}✘${NC}${WHITE}"]"`
HOST=`hostname`
DATA=`date +"%d%m%Y-%H%M"`
LOG=/tmp/$HOST-$DATA.txt
touch $LOG
#------------------------------------------
echo -e ${GREEN}"Verificar privilegios necessarios..."${NC}${WHITE}
echo
#Verificar se o Script executa como Root
if [ $(id -u) -ne 0 ] ; then
echo -e " Favor executar com privilegios administrativos" $FAIL | tee -a $LOG
exit
else
echo -e "Privilegios administrativos" $OK | tee -a $LOG
fi

echo -e ${NC}${GREEN}
echo -e '=============== ...Iniciando configuracao do sistema ... ==============='
echo -e ''
echo -e '--------------- ...Informacoes do host...-------------------------------'${NC}${WHITE}
hst=$(uname -n)
echo -e 'Hostname: '$hst | tee -a $LOG
ip=$(echo -e 'IPs:'`ip add |egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,3}[0-9]{1,3}'` | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,3}[0-9]{1,3}')
echo -e ${NC}${WHITE}"Rede:" ${NC}${RED} $ip ${NC} | tee $LOG
echo -e "-----------------------------------------------------------------------" | tee -a $LOG
echo -e "-----------------------------------------------------------------------"
echo -e ''${WHITE}

#Atualizar o sistema
echo -e "Deseja atualizar o sistema Update e Upgrade? Sim ou Não [S/n]"
read RESP
if [ "$RESP" = "S" ]; then
echo -e "Atualizando o sistema" $OK | tee -a $LOG
apt-get update -y && apt-get upgrade --fix-missing -y
else
echo -e "Atualizacao cancelada pelo usuario" $FAIL | tee -a $LOG
fi

echo -e "Adicionando o repositorio Kali no host"
echo -e ""
kali=$(grep "kali" /etc/apt/sources.list)
if [ "$kali" = "" ]; then
echo -e "Sem Repositorio" $FAIL
echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list
apt clean
apt update -y | tee erro
key=$(cat erro | grep -i "no_pubkey" | head -1 | cut -f 2 -d ":" | cut -f3 -d " ")
gpg --keyserver pgpkeys.mit.edu --recv-key $key
gpg -a --export $key | sudo apt-key add -
apt clean
apt update -y
rm erro
echo -e "\n"
echo -e "Repositorio Adicionado" $OK
else
apt clean && apt update -y
echo -e "\n"
echo -e "Maquina Pronta" $OK
fi

#Timezone
echo -e ''
echo -e "-- Configuracao do Timezone"
echo -e ''
zone=$(timedatectl status | grep -i "NTP service: n/a")
if [ "$zone" = "NTP service: n/a" ]; then
echo -e "Sem servico NTP" $FAIL | tee -a $LOG
else
echo -e "Servico habilitado" $OK
fi

#Exportar timezone
echo -e ''
echo -e "Atualizando o Timezone..."
echo -e ''
echo -e "Timezone America Sao Paulo" $OK | tee -a $LOG
timedatectl set-timezone America/Sao_Paulo
export TZ=America/Sao_Paulo

#instalar NTP
#echo -e "Instalar NTP" $OK | tee  -a $LOG
#apt-get install ntp
#apt-get install ntpdate
#ntpdate pool.ntp.br

echo -e ''
echo -e ${NC}${YELLOW}
echo -e ''
echo -e '=============== ...Instanlando Arsenal no Sistema ... ==============='
echo -e '---------------------------------------------------------------------'
echo -e ''
echo -e ${NC}${WHITE}
echo -e 'Aguarde alguns instantes...'
echo -e ''
echo -e "Ferramenta NMAP - https://nmap.org/"
echo -e ''
nmp=$(which nmap)
if [ "$nmp" = "" ]; then
echo -e "NMAP Nao Encontrado!" $FAIL | tee -a $LOG
echo -e ''
echo -e 'Instalando NMAP'
echo -e ''
apt-get install nmap -y
echo -e "\n"
echo  "NMAP INSTALADO COM SUCESSO" $OK | tee -a $LOG
else
echo -e 'NMAP Instalado' $OK | tee -a $LOG
fi


Kali:
Ferramenta Metasploit - https://www.metasploit.com/download
Kali:
Ferramenta Hydra - https://github.com/vanhauser-thc/thc-hydra
Kali:
Ferramenta DirSearch - https://github.com/maurosoria/dirsearch
Kali:
Ferramenta Ffuf - https://github.com/ffuf/ffuf
Kali:
Ferramenta OpenVas - https://www.openvas.org/
Kali:
Ferramenta Wireshark - https://www.wireshark.org/download.html
Kali:
Ferramenta TCPDump - https://www.tcpdump.org/
Kali:
Ferramenta Theharvester - https://github.com/laramies/theHarvester
Kali:
Ferramenta Responder - https://github.com/SpiderLabs/Responder
Kali:
Ferramenta FTP lib Python - 
Kali:
Ferramenta Mysql - https://www.mysql.com/downloads/
Kali:
Ferramenta SqlMap - https://sqlmap.org/
Kali:
Ferramenta Thc-IPv6 - https://github.com/vanhauser-thc/thc-ipv6
Kali:
Ferramenta Crackmapexec - https://github.com/byt3bl33d3r/CrackMapExec
Kali:
Ferramenta Whatweb - https://github.com/urbanadventurer/WhatWeb
Kali:
Ferramenta Bloodhound - https://github.com/BloodHoundAD/BloodHound/releases/tag/4.0.3
Kali:
Ferramenta neo4j - https://neo4j.com/download/
Kali:
Ferramenta nbtscan - https://github.com/scallywag/nbtscan
Kali:
Ferramenta Nikto https://github.com/sullo/nikto
Kali:
Ferramenta dirb - https://tools.kali.org/web-applications/dirb
Kali:
Ferramenta dirbuster - https://tools.kali.org/web-applications/dirbuster
Kali:
Ferramenta feroxbuster - https://github.com/epi052/feroxbuster
Kali:
Ferramenta Hashcat - https://hashcat.net/hashcat/
Kali:
Ferramenta John the Ripper https://www.openwall.com/john/
Kali:
Ferramenta GoBuster - https://github.com/OJ/gobuster
Kali:
Ferramenta wfuzz - https://github.com/xmendez/wfuzz
Kali:
Ferramenta Enum4linux - https://github.com/CiscoCXSecurity/enum4linux
Kali:
Ferramenta Impacket (SMB, psexec, etc) - https://github.com/SecureAuthCorp/impacket
Kali:
Ferramenta SecLists - https://github.com/danielmiessler/SecLists
Kali:
Ferramenta MSFVenom Payload Creator - https://github.com/g0tmi1k/msfpc



Ferramenta Nuclei - https://github.com/projectdiscovery/nuclei

Ferramenta Wappalyzer web - https://github.com/AliasIO/wappalyzer

Ferramenta LinEnum - https://github.com/rebootuser/LinEnum

Ferramenta AutoRecon - https://github.com/Tib3rius/AutoRecon

Ferramenta nmapAutomator - https://github.com/21y4d/nmapAutomator

Ferramenta Reconbot - https://github.com/Apathly/Reconbot

Ferramenta Raccoon - https://github.com/evyatarmeged/Raccoon

Ferramenta RustScan - https://github.com/RustScan/RustScan

Ferramenta BashScan - https://github.com/astryzia/BashScan

Ferramenta Recursive GoBuster - https://github.com/epi052/recursive-gobuster

Ferramenta goWAPT - https://github.com/dzonerzy/goWAPT

Ferramenta FinalRecon - https://github.com/thewhiteh4t/FinalRecon

Ferramenta updog - https://github.com/sc0tfree/updog

Ferramenta Reverse Shell Generator - https://github.com/cwinfosec/revshellgen

Ferramenta Windows Reverse Shell Generator - https://github.com/thosearetheguise/rev

Ferramenta Windows PHP Reverse Shell - https://github.com/Dhayalanb/windows-php-reverse-shell

Ferramenta PenTestMonkey Unix PHP Reverse Shell - http://pentestmonkey.net/tools/web-shells/php-reverse-shell

Ferramenta Windows Kernel Exploits - https://github.com/SecWiki/windows-kernel-exploits

Ferramenta AutoNSE - https://github.com/m4ll0k/AutoNSE

Ferramenta Linux Kernel Exploits - https://github.com/lucyoa/kernel-exploits

Ferramenta BruteX - https://github.com/1N3/BruteX

Ferramenta linprivchecker - https://www.securitysift.com/download/linuxprivchecker.py

Ferramenta Linux Exploit Suggester - https://github.com/mzet-/linux-exploit-suggester

Ferramenta Windows Exploit Suggester - https://github.com/bitsadmin/wesng

Ferramenta Windows Privilege Escalation Awesome Scripts (WinPEAS) - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS

Ferramenta Linux Privilege Escalation Awesome Script (LinPEAS) - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

Ferramenta Get GTFOBins - https://github.com/CristinaSolana/ggtfobins

Ferramenta sudo_killer - https://github.com/TH3xACE/SUDO_KILLER

Ferramenta PTF - https://github.com/trustedsec/ptf


echo -e "<p>Elaborado por: Roberto Lima | " >> $LOG
echo -e "</div></body></html>" >> $LOG
echo -e "Instalacao deste sistema foi realizada em" $DATA  
