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
hst=$(`uname -n`)
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
