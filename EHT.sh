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
# Renato.Borbolla  		2021.11.16              0.3
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
sleep 3s
#Verificar se o Script executa como Root
if [ $(id -u) -ne 0 ] ; then
echo -e " Favor executar com privilegios administrativos" $FAIL | tee -a $LOG
echo -e ""
exit
else
echo -e "Privilegios administrativos" $OK | tee -a $LOG
echo -e ""
fi

echo -e ${NC}${GREEN}
echo -e ""
echo -e '=============== ...Iniciando configuracao do sistema ... ==============='
echo -e ''
echo -e '--------------- ...Informacoes do host...-------------------------------'${NC}${WHITE}
hst=$(uname -n)
user=$(id)
sleep 3s
echo -e 'User: '$user | tee -a $LOG
echo -e 'Hostname: '$hst | tee -a $LOG
ip=$(echo -e 'IPs:'`ip add |egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,3}[0-9]{1,3}'` | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,3}[0-9]{1,3}')
echo -e ${NC}${WHITE}"Rede:" ${NC}${RED} $ip ${NC} | tee $LOG
echo -e "-----------------------------------------------------------------------" | tee -a $LOG
echo -e "-----------------------------------------------------------------------"
sleep 3s
echo -e ''${WHITE}

#Atualizar o sistema
echo -e "Deseja atualizar o sistema Update e Upgrade? Sim ou Não [S/n]"
echo -e ""
read RESP
if [ "$RESP" = "S" ]; then
echo -e "Atualizando o sistema" $OK | tee -a $LOG
sleep 3s
apt clean && apt-get update -y && apt-get upgrade --fix-missing -y
else
echo -e ""
echo -e "Atualizacao cancelada pelo usuario" $FAIL | tee -a $LOG
sleep 3s
echo -e ""
fi

echo -e ""
echo -e "Verificando a existencia do repositorio Kali na maquina."
echo -e ""
sleep 3s
kali=$(grep "kali" /etc/apt/sources.list)
if [ "$kali" = "" ]; then
	echo -e ""
echo -e "Sem Repositorio" $FAIL
sleep 3s
echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list
apt clean
apt update -y | tee erro > $OFF
key=$(cat erro | grep -i "no_pubkey" | head -1 | cut -f 2 -d ":" | cut -f3 -d " ")
gpg --keyserver pgpkeys.mit.edu --recv-key $key
gpg -a --export $key | sudo apt-key add -
apt clean
sleep 3s
apt update -y > $OFF
rm erro
echo -e "\n"
echo -e "Repositorio Adicionado" $OK
echo -e ""
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
echo -e '====== ...Instanlando Arsenal de Ferramentas no Sistema ... ========='
echo -e '---------------------------------------------------------------------'
echo -e ''
echo -e ${NC}${WHITE}
echo -e 'Aguarde alguns instantes...'
echo -e ''
echo -e 'Instalando as Ferramentas:'
sleep 3s
apt install htop bettercap crackmapexec tcpdump httpie powershell rdesktop unzip nmap proxychains exploitdb metasploit-framework rlwrap python3 python3-pip impacket-scripts jq golang bloodhound burpsuite seclists leafpad enum4linux snmpenum curl feroxbuster nbtscan nikto onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf zip sqlmap responder hydra whatweb neo4j dirbuster hashcat john gobuster dirb enum4linux msfpc --fix-missing -y > $OFF
pip3 install pypykatz impacket pyftpdlib mysql
sleep 3s
clear
echo -e 'Ferramentas instaladas:'
echo -e ''
echo -e '
Metasploit - https://www.metasploit.com/download
Hydra - https://github.com/vanhauser-thc/thc-hydra
DirSearch - https://github.com/maurosoria/dirsearch
Ffuf - https://github.com/ffuf/ffuf
OpenVas - https://www.openvas.org/
Wireshark - https://www.wireshark.org/download.html
TCPDump - https://www.tcpdump.org/
Theharvester - https://github.com/laramies/theHarvester
Responder - https://github.com/SpiderLabs/Responder
FTP lib Python - pyftpdlib
Mysql - https://www.mysql.com/downloads/
SqlMap - https://sqlmap.org/
Thc-IPv6 - https://github.com/vanhauser-thc/thc-ipv6
Crackmapexec - https://github.com/byt3bl33d3r/CrackMapExec
Whatweb - https://github.com/urbanadventurer/WhatWeb
Bloodhound - https://github.com/BloodHoundAD/BloodHound/releases/tag/4.0.3
neo4j - https://neo4j.com/download/
nbtscan - https://github.com/scallywag/nbtscan
Nikto https://github.com/sullo/nikto
dirb - https://tools.kali.org/web-applications/dirb
dirbuster - https://tools.kali.org/web-applications/dirbuster
feroxbuster - https://github.com/epi052/feroxbuster
Hashcat - https://hashcat.net/hashcat/
John the Ripper https://www.openwall.com/john/
GoBuster - https://github.com/OJ/gobuster
wfuzz - https://github.com/xmendez/wfuzz
Enum4linux - https://github.com/CiscoCXSecurity/enum4linux
Impacket (SMB, psexec, etc) - https://github.com/SecureAuthCorp/impacket
SecLists - https://github.com/danielmiessler/SecLists
MSFVenom Payload Creator - https://github.com/g0tmi1k/msfpc'
fi

sleep 10s
clear
echo -e ''
echo -e 'Instalando as Ferramentas Externas:'
echo -e ''
echo -e '
Ferramenta Externa: Nuclei - https://github.com/projectdiscovery/nuclei
Ferramenta Externa: Wappalyzer web - https://github.com/AliasIO/wappalyzer
Ferramenta Externa: LinEnum - https://github.com/rebootuser/LinEnum
Ferramenta Externa: AutoRecon - https://github.com/Tib3rius/AutoRecon
Ferramenta Externa: nmapAutomator - https://github.com/21y4d/nmapAutomator
Ferramenta Externa: Reconbot - https://github.com/Apathly/Reconbot
Ferramenta Externa: Raccoon - https://github.com/evyatarmeged/Raccoon
Ferramenta Externa: RustScan - https://github.com/RustScan/RustScan
Ferramenta Externa: BashScan - https://github.com/astryzia/BashScan
Ferramenta Externa: Recursive GoBuster - https://github.com/epi052/recursive-gobuster
Ferramenta Externa: goWAPT - https://github.com/dzonerzy/goWAPT
Ferramenta Externa: FinalRecon - https://github.com/thewhiteh4t/FinalRecon
Ferramenta Externa: updog - https://github.com/sc0tfree/updog
Ferramenta Externa: Reverse Shell Generator - https://github.com/cwinfosec/revshellgen
Ferramenta Externa: Windows Reverse Shell Generator - https://github.com/thosearetheguise/rev
Ferramenta Externa: Windows PHP Reverse Shell - https://github.com/Dhayalanb/windows-php-reverse-shell
Ferramenta Externa: PenTestMonkey Unix PHP Reverse Shell - http://pentestmonkey.net/tools/web-shells/php-reverse-shell
Ferramenta Externa: Windows Kernel Exploits - https://github.com/SecWiki/windows-kernel-exploits
Ferramenta Externa: AutoNSE - https://github.com/m4ll0k/AutoNSE
Ferramenta Externa: Linux Kernel Exploits - https://github.com/lucyoa/kernel-exploits
Ferramenta Externa: BruteX - https://github.com/1N3/BruteX
Ferramenta Externa: linprivchecker - https://www.securitysift.com/download/linuxprivchecker.py
Ferramenta Externa: Linux Exploit Suggester - https://github.com/mzet-/linux-exploit-suggester
Ferramenta Externa: Windows Exploit Suggester - https://github.com/bitsadmin/wesng
Ferramenta Externa: Windows Privilege Escalation(WinPEAS) - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
Ferramenta Externa: Linux Privilege Escalation (LinPEAS) - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
Ferramenta Externa: Get GTFOBins - https://github.com/CristinaSolana/ggtfobins
Ferramenta Externa: sudo_killer - https://github.com/TH3xACE/SUDO_KILLER
Ferramenta Externa: PTF - https://github.com/trustedsec/ptf'
sleep 12s
mkdir /tools && /tools
git clone https://github.com/projectdiscovery/nuclei > $OFF
git clone https://github.com/AliasIO/wappalyzer > $OFF
git clone https://github.com/rebootuser/LinEnum > $OFF
git clone https://github.com/Tib3rius/AutoRecon > $OFF
git clone https://github.com/21y4d/nmapAutomator > $OFF
git clone https://github.com/Apathly/Reconbot > $OFF
git clone https://github.com/evyatarmeged/Raccoon > $OFF
git clone https://github.com/RustScan/RustScan > $OFF
git clone https://github.com/astryzia/BashScan > $OFF
git clone https://github.com/epi052/recursive-gobuster > $OFF
git clone https://github.com/dzonerzy/goWAPT > $OFF
git clone https://github.com/thewhiteh4t/FinalRecon > $OFF
git clone https://github.com/sc0tfree/updog > $OFF
git clone https://github.com/cwinfosec/revshellgen > $OFF
git clone https://github.com/thosearetheguise/rev > $OFF
git clone https://github.com/Dhayalanb/windows-php-reverse-shell > $OFF
#http://pentestmonkey.net/tools/web-shells/php-reverse-shell
git clone https://github.com/SecWiki/windows-kernel-exploits > $OFF
git clone https://github.com/m4ll0k/AutoNSE > $OFF
git clone https://github.com/lucyoa/kernel-exploits > $OFF
git clone https://github.com/1N3/BruteX > $OFF
wget https://www.securitysift.com/download/linuxprivchecker.py
git clone https://github.com/mzet-/linux-exploit-suggester > $OFF
git clone https://github.com/bitsadmin/wesng > $OFF
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite > $OFF
git clone https://github.com/CristinaSolana/ggtfobins > $OFF
git clone https://github.com/TH3xACE/SUDO_KILLER > $OFF
git clone https://github.com/trustedsec/ptf > $OFF
echo -e ''
echo -e 'Aplicando as configuracoes das Ferramentas Externas...'
echo -e ''

echo -e "<p>Elaborado por: Roberto Lima | Renato Borbolla" >> $LOG
echo -e "</div></body></html>" >> $LOG
echo -e "Instalacao deste sistema foi realizada em" $DATA  
