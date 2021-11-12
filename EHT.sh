#!/bin/bash
###############################################################################
# Descricao: Script EHT - Gray Box
#------------------------------------------------------------------------------
# Usabilidade:
# - ./EHT.sh
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# ID                    Date                    version
# Roberto.Lima  2021.11.11                       0.1
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
OK=`echo "["${NC}${GREEN}✔${NC}${WHITE}"]"`
FAIL=`echo "["${NC}${RED}✘${NC}${WHITE}"]"`
HOST=`hostname`
DATA=`date +"%d%m%Y-%H%M"`
LOG=/root/Desktop/$HOST-$DATA.txt
touch $LOG
#------------------------------------------
echo "Verificar privilegios necessarios..."
echo
#Verificar se o Script executa como Root
if [ $(id -u) -ne 0 ] ; then
echo " Favor executar com privilegios administrativos" $FAIL >> $LOG
echo "Privilegios administrativos" $FAIL >> $LOG
exit
else
echo "Privilegios administrativos" $OK >> $LOG
fi

echo ${NC}${YELLOW}
echo '=============== ...Iniciando configuracao do sistema ... ==============='
echo ''
echo '--------------- ...Informacoes do host...-------------------------------'
echo 'Hostname: '`uname -n` >> $LOG
uname -n 
echo 'IPs:'`ifconfig |egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}'` >> $LOG
echo 'IPs:'`ifconfig |egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}'`
echo "-----------------------------------------------------------------------" >> $LOG
echo "-----------------------------------------------------------------------"
echo ''

#Atualizar o sistema
echo "Deseja atualizar o sistema Update e Upgrade? Sim ou Não [S/n]"
read RESP
if [ "$RESP" = "S" ]; then
echo "Atualizando o sistema" $OK >> $LOG
apt-get install update && apt-get install upgrade -y
else
echo "Atualizacao cancelada pelo usuario" $FAIL >> $LOG
fi

#Timezone
echo "Timezone"
timedatectl status |grep -i "NTP service: n/a" > $OFF
if [ "$?" = "0" ]; then
echo "Timezone habilitado" $FAIL >> $LOG
else
echo "Timezone habilitado" $OK >> $LOG
fi

#Exportar timezone
echo "Timezone America Sao Paulo" $OK >> $LOG
timedatectl set-timezone America/Sao_Paulo
export TZ=America/Sao_Paulo

#instalar NTP
#echo "Instalar NTP" $OK >> $LOG
#apt-get install ntp
#apt-get install ntpdate
#ntpdate pool.ntp.br

echo ''
echo '=============== ...Instanlando Arsenal no sistema ... ==============='
echo '---------------------------------------------------------------------'
echo ''
echo 'Aguarde alguns instantes...'
echo ''
echo "NMAP"
echo 'https://nmap.org/'
file /usr/share/nmap* > $OFF
if [ "$?" = "0" ]; then
echo "NMAP econtrado" $OK >> $LOG
else
echo 'NMAP nao econtrado' $FAIL >> $LOG
echo 'NMAP nao econtrado'
echo 'Instalando NMAP'
apt-get install nmap -y 
echo  "NMAP OK" $OK >> $LOG
fi

Metasploit
https://www.metasploit.com/download

Hydra
https://github.com/vanhauser-thc/thc-hydra

Nikto
https://cirt.net/Nikto2
https://github.com/sullo/nikto

DirSearch
https://github.com/maurosoria/dirsearch

Ffuf
https://github.com/ffuf/ffuf

Nuclei
https://github.com/projectdiscovery/nuclei

OpenVas
https://www.openvas.org/

Wireshark
https://www.wireshark.org/download.html

TCPDump
https://www.tcpdump.org/

Theharvester
https://github.com/laramies/theHarvester

Responder
https://github.com/SpiderLabs/Responder

Wappalyzer web
https://github.com/AliasIO/wappalyzer

FTP lib Python

Mysql
https://www.mysql.com/downloads/

SqlMap
https://sqlmap.org/

LinEnum
https://github.com/rebootuser/LinEnum

Thc-IPv6
https://github.com/vanhauser-thc/thc-ipv6

AutoRecon
https://github.com/Tib3rius/AutoRecon

nmapAutomator
https://github.com/21y4d/nmapAutomator

Reconbot
https://github.com/Apathly/Reconbot

Raccoon
https://github.com/evyatarmeged/Raccoon

RustScan
https://github.com/RustScan/RustScan

BashScan
https://github.com/astryzia/BashScan

GoBuster
https://github.com/OJ/gobuster

Recursive GoBuster
https://github.com/epi052/recursive-gobuster

wfuzz
https://github.com/xmendez/wfuzz

goWAPT
https://github.com/dzonerzy/goWAPT

Crackmapexec
https://github.com/byt3bl33d3r/CrackMapExec

Whatweb
https://github.com/urbanadventurer/WhatWeb

Bloodhound
https://github.com/BloodHoundAD/BloodHound/releases/tag/4.0.3

neo4j
https://neo4j.com/download/

nbtscan
https://github.com/scallywag/nbtscan

Nikto
https://github.com/sullo/nikto

dirb
https://tools.kali.org/web-applications/dirb

dirbuster
https://tools.kali.org/web-applications/dirbuster

feroxbuster
https://github.com/epi052/feroxbuster

FinalRecon
https://github.com/thewhiteh4t/FinalRecon

Impacket (SMB, psexec, etc)
https://github.com/SecureAuthCorp/impacket

updog
https://github.com/sc0tfree/updog

SecLists
https://github.com/danielmiessler/SecLists

Reverse Shell Generator
https://github.com/cwinfosec/revshellgen

Windows Reverse Shell Generator
https://github.com/thosearetheguise/rev

MSFVenom Payload Creator
https://github.com/g0tmi1k/msfpc

Windows PHP Reverse Shell
https://github.com/Dhayalanb/windows-php-reverse-shell

PenTestMonkey Unix PHP Reverse Shell
http://pentestmonkey.net/tools/web-shells/php-reverse-shell

Windows Kernel Exploits
https://github.com/SecWiki/windows-kernel-exploits

AutoNSE
https://github.com/m4ll0k/AutoNSE

Linux Kernel Exploits
https://github.com/lucyoa/kernel-exploits

BruteX
https://github.com/1N3/BruteX

Hashcat
https://hashcat.net/hashcat/

John the Ripper
https://www.openwall.com/john/

LinEnum
https://github.com/rebootuser/LinEnum

linprivchecker
https://www.securitysift.com/download/linuxprivchecker.py

Enum4linux
https://github.com/CiscoCXSecurity/enum4linux

Linux Exploit Suggester
https://github.com/mzet-/linux-exploit-suggester

Windows Exploit Suggester
https://github.com/bitsadmin/wesng

Windows Privilege Escalation Awesome Scripts (WinPEAS)
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS

Linux Privilege Escalation Awesome Script (LinPEAS)
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

Get GTFOBins
https://github.com/CristinaSolana/ggtfobins

sudo_killer
https://github.com/TH3xACE/SUDO_KILLER

PTF
https://github.com/trustedsec/ptf