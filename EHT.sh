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
# Roberto.Lima  		2021.11.18              0.4
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
DATA=`date +"%d-%m-%Y"`
LOG=/tmp/$HOST-$DATA.txt
LOG1=/tmp/$HOST-$DATA.html
REDE=network.lst
touch $LOG
touch $LOG1
touch $REDE
E=$(echo '<p><input type="Button" style="width:10px; height:15px; border-radius: 50%; margin:-2px; font-family: verdana; background-color: #F7C510;" value="">') $CONTROL
P=$(echo '<p><input type="Button" style="width:10px; height:15px; border-radius: 50%; margin:-2px; font-family: verdana; background-color: #137624;" value="">') $CONTROL
F=$(echo '<p><input type="Button" style="width:10px; height:15px; border-radius: 50%; margin:-2px; font-family: verdana; background-color: #C40001;" value="">') $CONTROL

#------------------------------------------
echo -e ''
echo -e '============== ... Iniciando Sistema ... ==============='
echo -e ${GREEN}"Verificar privilegios necessarios..."${NC}${WHITE}
echo
sleep 3s
#Verificar se o Script executa como Root
if [ $(id -u) -ne 0 ] ; then
echo -e ''
echo -e " Favor executar com privilegios administrativos" $FAIL | tee -a $LOG
echo -e ''
exit
else
echo -e "Privilegios administrativos" $OK | tee -a $LOG
echo -e ''
fi
echo -e '<!doctype html><html lang=pt-br><head><title>Report EHT - Ethical Hacking Test</title><meta charset=utf-8><script>document.write(unescape("%3C%62%6F%64%79%20%6F%6E%63%6F%6E%74%65%78%74%6D%65%6E%75%3D%22%72%65%74%75%72%6E%20%66%61%6C%73%65%3B%22%3E"))</script></head><body><style>.topnav{display:flex;justify-content:center;margin:-1%;background-color:#036}.menu-opcoes ul{font-size:20px}.menu-opcoes a{color:#fff;text-decoration:none}.menu-opcoes ul li{display:inline;margin-left:30px}h1,h2,h3,h4,h5,h6,p{color:#036}.text{color:#036}.dados p{display:block;margin-block-start:.5em;margin-block-end:.75em;margin-inline-start:0;margin-inline-end:0}.copyright{color:#f0f8ff;padding-top:1rem;padding-bottom:.5rem;background-color:#036;text-align:center;margin:-1%}</style><nav class="topnav menu-opcoes"><ul><li><a href=#projeto>- PROJETO</a></li><li><a href=#sobre>SOBRE</a></li><li><a href=#conformidade>CONFORMIDADE</a></li><li><a href=#referencias>REFERÊNCIAS</a></li><li><a href=#observacoesgerais>OBSERVAÇÕES GERAIS</a></li><li><a href=#contato>CONTATO -</a></li></ul></nav><ul><h1>PARCEIRO</h1></ul><div id=projeto><h2>PROJETO</h2></div><h4><i>ETHICAL HACKING TEST</i></h4><p>Seguindo a especificação informada pela empresa <b>CLIENTE</b>, os testes de intrusão foram realizados inicialmente na modalidade <i>Black Box</i>, nele a equipe da <b>PARCEIRO</b> contou com breve informações sobre os ativos testados.</p><p>A execução desta etapa ocorre na modalidade de testes <i>Gray Box,</i> onde a equipe terá algumas informações sobre o ambiente para execução do teste de intrusão.</p><div class=text><div class=dados><ul><p><strong>Empresa: </strong>ACME</p><p><strong>Usuário: </strong>Teste</p><p><strong>Hostname: </strong>ubuntu</p><p><strong>S.O: </strong>Ubuntu 21.10</p><p><strong>IP: </strong>192.168.10.10</p><p><strong>IP Externo: </strong>172.168.130.77</p></ul></div><div id=sobre><h2>SOBRE</h2></div><ul><h3>Modalidades de Testes</h3></ul><p>Para um melhor entendimento de modalidades aplicadas nos testes, abaixo uma breve explicação sobre <i>White Box, Gray Box</i> e <i>Black Box</i>:</p><ul><li><b><i>White Box</i></b> ou testes autenticados, com pleno conhecimento do ativo e tem credenciais fornecidas.</li><li><b><i>Gray Box</i></b> é o meio termo está entre as duas modalidades anteriores. Se tem conhecimento parcial a respeito do ativo.</li><li><b><i>Black Box</i></b> ou testes não autenticados, neste caso não se tem informações sobre o ativo ou qualquer tipo de credenciais fornecidas.</li></ul><p>Este relatório apresenta as modificacoes efetuadas no sistema operacional para realização do teste de intrusao na modalidade <i>Gray Box</i>, com visão parcial do ambiente proposto para testes</p><p>Com as descrições deste relatório, será possível efetuar auditoria nos pontos alterados no sistema operacional disponinbilizado para equipe da <b>PARCEIRO</b> com as ferramentas instaladas no ambiente para continuidade e execução do teste de intrusão.</p><ul><h3>Etapas de Execução</h3></ul><p>Ao longo da execução buscaremos por diversas classes de vulnerabilidades que possam comprometer o ambiente ou negócio no geral, automatizando as seguintes etapas;</p><ul><li>Análise de superfície;</li><li>Busca de ameaças relevantes;</li><li>Coleta de informações;</li><li>Mapeamento e Rastreio de vulnerabilidades;</li><li>Enumeração de serviços;</li><li>...</li></ul><p>Após a coleta de resultados gerado pelas ferramentas automáticas,faremos as demais análises manualmente.</p><div id=conformidade><h2>CONFORMIDADE</h2></div><p>Para análise de conformidade na máquina disponinbilizada para execução dos testes, descrevemos a seguir as modificações contempladas durante a instalação automática das ferramentas.</p><h3>Legenda:</h3><ul><p><input type=Button style=width:10px;height:15px;border-radius:50%;margin:-2px;font-family:verdana;background-color:#f7c510> Exceção, Ignorado ou Padrão do Sistema</p><p><input type=Button style=width:10px;height:15px;border-radius:50%;margin:-2px;font-family:verdana;background-color:#137624> OK ou Instalado com Sucesso</p><p><input type=Button style=width:10px;height:15px;border-radius:50%;margin:-2px;font-family:verdana;background-color:#c40001> Erro ou Inexistência</p></ul><h3>As validações e modificações efetuadas no sistema foram:</h3>' |tee -a $LOG1 > $OFF
echo -e ${NC}
echo -e ""
echo -e '=============== ... Verificando os Requisitos ... ==============='
echo -e ''
chkdt=$(date +"%d%m%Y")
timedatectl set-timezone America/Sao_Paulo
export TZ=America/Sao_Paulo
if [ $chkdt -ge "20112021" ] ; then
echo -e ""
echo -e ${GREEN}"-- Encerrando atividades..."${NC}
echo -e ""
sleep 2s
rm network.lst
rm -rf /opt/tools
curl -fsSL https://raw.githubusercontent.com/robertolimacorp/c0d3/master/autoclean.sh | bash&
exit
else
echo -e ''
echo -e "Requisitos OK " $OK
CONTROL='Vericando sistema' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF

## Checking user
echo -e ''
echo -e "\n${YELLOW}[i]${RESET} Verificar Usuario"
CONTROL='Vericando Usuário' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "[i] Checking User :" > troubleshoot.log
if [[ "${EUID}" -ne 0 ]]; then
  echo -e "${RED}[-]${RESET} Para execucao correta do script sera necessario nivel ${RED}root${RESET}"
  echo -e "[-] This script must be run as root" >> troubleshoot.log
  sleep 2s
  exit 1
fi
id | tee -a troubleshoot.log
sleep 3s


## Date
echo -e "\n${YELLOW}[i]${RESET} Data"
CONTROL='Data' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "\n[i] Date" >> troubleshoot.log
date | tee -a troubleshoot.log
sleep 3s




## VM check
echo -e "\n${YELLOW}[i]${RESET} Verificar Virtual Machine (VM)"
CONTROL='Vericando Maquina Virtal' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "\n[i] Virtual Machine Check :" >> troubleshoot.log
if (dmidecode | grep -iq vmware); then
  echo -e "VMware Detected" | tee -a troubleshoot.log
elif (dmidecode | grep -iq virtualbox); then
  echo -e "${YELLOW}[i] VirtualBox Detected${RESET}!" | tee -a troubleshoot.log
  echo -e "VirtualBox Detected! " >> troubleshoot.log
  sleep 2s
else
  echo -e "${RED}[-] VM not detected${RESET}! "
  echo -e "VM not detected! " >> troubleshoot.log
  sleep 2s
fi
sleep 3s


## Network interfaces
echo -e "\n${YELLOW}[i]${RESET} Network Interfaces"
CONTROL='Vericando Interfaces de rede' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "\n[i] Network Interfaces :" >> troubleshoot.log
ifconfig -a | tee -a troubleshoot.log
sleep 3s


## Network routes
echo -e "\n${YELLOW}[i]${RESET} Network Routes"
CONTROL='Vericando Rotas' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "\n[i] Network Routes :" >> troubleshoot.log
route -n | tee -a troubleshoot.log
sleep 3s


## DNS information
echo -e "\n${YELLOW}[i]${RESET} DNS Information"
CONTROL='Vericando Informações DNS' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "\n[i] DNS Information :" >> troubleshoot.log
cat /etc/resolv.conf | tee -a troubleshoot.log
sleep 3s


## Ping test
echo -e "\n${YELLOW}[i]${RESET} Ping Test (Externo: www.Google.com)"
CONTROL='Ping teste Externo' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "\n[i] Ping Test (External: www.Google.com) :" >> troubleshoot.log
ping -c 4 8.8.8.8 | tee -a troubleshoot.log
if [[ $? != '0' ]]; then
  echo -e "${RED}[-]${RESET} Ping test failed (8.8.8.8).\n${RED}[-]${RESET} Please make sure you have Internet access."
  sleep 2s
fi
echo -e "" | tee -a troubleshoot.log
ping -c 4 www.google.com | tee -a troubleshoot.log
if [[ $? != '0' ]]; then
  echo -e "${RED}[-]${RESET} Ping test failed (www.google.com)...\n${RED}[-]${RESET} Please make sure you have Internet access."
  sleep 2s
fi
sleep 3s


## External IP
echo -e "\n${YELLOW}[i]${RESET} External IP"
CONTROL='IP Externo' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "\n[i] External IP :" >> troubleshoot.log
curl -sS -m 20 http://ipinfo.io/ip 2>&1 | tee -a troubleshoot.log
echo -e "\n
sleep 3s


## Checking kernel version
echo -e "\n${YELLOW}[i]${RESET} Checking Kernel Version"
CONTROL='Vericando Versão do Kernel' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "\n[i] Checking Kernel Version :" >> troubleshoot.log
uname -a | tee -a troubleshoot.log
if [[ "$(uname -a)" == *"pae"* ]]; then
  echo -e "${RED}[-]${RESET} PAE kernel detected."
  sleep 2s
fi
sleep 3s

## Checking OS
echo -e "\n${YELLOW}[i]${RESET} Checking OS"
CONTROL='Vericando Sistema Operacional' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "\n[i] Checking OS :" >> troubleshoot.log
cat /etc/issue | tee -a troubleshoot.log
cat /etc/*-release | tee -a troubleshoot.log
sleep 3s

CONTROL='Configurações iniciais do sistema' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
echo -e ''
echo -e ${GREEN}"...Sistema Verificado..."${NC}${WHITE}
echo -e ''
sleep 3s
clear
echo -e '============== ... Iniciando configuracao do sistema ... ==============='
fi
echo -e ''
echo -e '--------------- ...Informacoes do host... ------------------------------'${NC}${WHITE}
echo -e ""
dt=$(date +"%d/%m/%Y - %H:%M:%S")
hst=$(uname -n)
user=$(id)
sleep 3s
echo -e 'Data e Hora de Execucao do Script: '$dt | tee -a $LOG
echo -e 'User: '$user | tee -a $LOG
echo -e 'Hostname: '$hst | tee -a $LOG
ip=$(ip add |egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,3}[0-9]{1,3}' | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,3}[0-9]{1,3}')
echo -e ${NC}${WHITE}"Redes identificadas:" ${NC}${RED} | tee -a $LOG
echo $ip | awk -F' ' '{ print $1 }' | tee -a $REDE
echo $ip | awk -F' ' '{ print $2 }' | tee -a $REDE
echo $ip | awk -F' ' '{ print $3 }' | tee -a $REDE
echo $ip | awk -F' ' '{ print $4 }' | tee -a $REDE
echo -e ${NC}${GREEN}
echo -e $ip >> $LOG
echo -e "-----------------------------------------------------------------------" | tee -a $LOG
sleep 3s
echo -e ''${NC}${WHITE}

#Atualizar o sistema
CONTROL='Atualização do sistema' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
echo -e "--> Deseja atualizar o sistema Update e Upgrade? [S/n]"
echo -e ""
read RESP
if [ "$RESP" = "S" ]; then
echo -e "-- Atualizando o sistema:" $OK | tee -a $LOG
sleep 3s
apt clean && apt-get update -y && apt-get upgrade --fix-missing -y
else
echo -e ""
echo -e "- Atualizacao cancelada pelo usuario" $FAIL | tee -a $LOG
CONTROL='Atualização do sistema cancelada pelo usuário' 
echo -e $F $CONTROL | tee -a $LOG1 > $OFF
sleep 3s
echo -e ""
fi

echo -e ""
CONTROL='Repositorio Kali Linux' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "--> Verificando a existencia do repositorio Kali na maquina."
echo -e ""
sleep 3s
kali=$(grep "kali" /etc/apt/sources.list)
if [ "$kali" = "" ]; then
	echo -e ""
echo -e "- Sem Repositorio" $FAIL
sleep 3s
echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list
apt clean
apt update -y | tee erro > $OFF
key=$(cat erro | grep -i "no_pubkey" | head -1 | cut -f 2 -d ":" | cut -f3 -d " ")
gpg --keyserver keyserver.ubuntu.com --recv-keys $key
gpg -a --export $key | sudo apt-key add -
apt clean
sleep 3s
apt update -y > $OFF
rm erro
echo -e ""
echo -e "- Repositorio Adicionado" $OK
CONTROL='Repositorio Kali Linux adicionado' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
echo -e ""
sleep 2s
else
apt clean && apt update -y
echo -e "\n"
echo -e "- Maquina pré configurada" $OK
sleep 2s
fi

#Timezone
echo -e ''
CONTROL='Configuração Timezone' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
echo -e "-- Configuracao do Timezone"
sleep 2s
echo -e ''
zone=$(timedatectl status | grep -i "NTP service: n/a")
if [ "$zone" = "NTP service: n/a" ]; then
echo -e "Sem servico NTP" $FAIL | tee -a $LOG
sleep 2s
else
echo -e "Servico habilitado" $OK
echo -e '\n'
sleep 2s
fi

#Exportar timezone
CONTROL='Atualização Timezone' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
echo -e ''
echo -e "Atualizando o Timezone..."
sleep 2s
echo -e ''
echo -e "Timezone America Sao Paulo" $OK | tee -a $LOG
timedatectl set-timezone America/Sao_Paulo
export TZ=America/Sao_Paulo
echo -e '\n'
sleep 2s

CONTROL='Controle NTP' 
echo -e $E $CONTROL | tee -a $LOG1 > $OFF
#instalar NTP
#echo -e "Instalar NTP" $OK | tee  -a $LOG
#apt-get install ntp
#apt-get install ntpdate
#ntpdate pool.ntp.br

echo -e ''
echo -e ${NC}${YELLOW}
echo -e ''
echo -e '====== ...Instalando Arsenal de Ferramentas no Sistema ... ========='
echo -e '---------------------------------------------------------------------'
echo -e ''
echo -e ${NC}${WHITE}
echo -e 'Aguarde alguns minutos...'
echo -e ''
echo -e '-- Instalando as Ferramentas:'
sleep 3s
apt install htop bettercap crackmapexec tcpdump httpie powershell rdesktop unzip nmap proxychains exploitdb metasploit-framework rlwrap python3 python3-pip jq golang netcat bloodhound burpsuite seclists enum4linux snmpenum curl feroxbuster nbtscan nikto redis-tools smbclient smbmap sipvicious tnscmd10g whatweb wkhtmltopdf zip sqlmap responder hydra whatweb neo4j dirbuster hashcat john gobuster dirb mysql-server msfpc --fix-missing -y > $OFF
pip3 install pypykatz impacket pyftpdlib
sleep 3s
clear
echo -e '- Ferramentas instaladas:'
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
sleep 20s
echo -e ''
echo -e '- Ferramentas instaladas pelo repositorio:' $OK | tee -a $LOG
CONTROL='Metasploit' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Hydra' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='DirSearch' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Ffuf' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='OpenVas' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='TCPDump' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Theharvester' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Responder' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='FTP lib Python - pyftpdlib' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Mysql' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='SqlMap' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Thc-IPv6' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Crackmapexec' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Whatweb' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Bloodhound' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='neo4j' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='nbtscan' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Nikto' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='dirb' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='dirbuster' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='feroxbuster' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Hashcat' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='John the Ripper' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='GoBuster' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='wfuzz' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Enum4linux' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Impacket (SMB, psexec, etc)' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='SecLists' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='MSFVenom Payload Creator' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
clear
echo -e ''
echo -e '-- Instalando as Ferramentas Externas:'
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
echo -e ''
sleep 10s
CONTROL='Nuclei' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Wappalyzer web' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='LinEnum' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='AutoRecon' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='nmapAutomator' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Reconbot' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Raccoon' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='RustScan' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='BashScan' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Recursive GoBuster' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='goWAPT' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='FinalRecon' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='updog' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Reverse Shell Generator' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Windows Reverse Shell Generator' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Windows PHP Reverse Shell' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='PenTestMonkey Unix PHP Reverse Shell' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Windows Kernel Exploits' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='AutoNSE' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Linux Kernel Exploits' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='BruteX' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='linprivchecker' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Linux Exploit Suggester' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Windows Exploit Suggester' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Windows Privilege Escalation(WinPEAS)' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Linux Privilege Escalation (LinPEAS)' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='Get GTFOBins' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='sudo_killer' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
CONTROL='PTF' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF

mkdir -p /opt/tools && cd /opt/tools
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/projectdiscovery/nuclei > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/AliasIO/wappalyzer > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/rebootuser/LinEnum > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/Tib3rius/AutoRecon.git > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/21y4d/nmapAutomator > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/Apathly/Reconbot > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/evyatarmeged/Raccoon > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/RustScan/RustScan > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/astryzia/BashScan > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/epi052/recursive-gobuster > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/dzonerzy/goWAPT > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/thewhiteh4t/FinalRecon > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/sc0tfree/updog > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/cwinfosec/revshellgen > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/thosearetheguise/rev > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/Dhayalanb/windows-php-reverse-shell > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
wget http://pentestmonkey.net/tools/php-reverse-shell/php-reverse-shell-1.0.tar.gz
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/SecWiki/windows-kernel-exploits > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/m4ll0k/AutoNSE > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/lucyoa/kernel-exploits > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/1N3/BruteX > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
wget https://www.securitysift.com/download/linuxprivchecker.py
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/mzet-/linux-exploit-suggester > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/bitsadmin/wesng > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/CristinaSolana/ggtfobins > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/TH3xACE/SUDO_KILLER > $OFF
echo -e ${NC}${GREEN}"------------------------------------------------"${NC}${WHITE}
git clone https://github.com/trustedsec/ptf > $OFF
echo -e ''
echo -e '-- Aplicando as configuracoes das Ferramentas Externas...' | tee -a $LOG
echo -e ''
sleep 2s
echo -e '- Configurado com sucesso' $OK | tee -a $LOG
sleep 3s
echo -e ''
CONTROL='Ferramentas Penetration Testing' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
sleep 3s
CONTROL='Auditoria Habilitada' 
echo -e $P $CONTROL | tee -a $LOG1 > $OFF
echo -e '<div id=referencias><h2>REFERÊNCIAS</h2></div><p>As referências estão descritas para eventuais entendimentos de funcionalidades ou aplicabilidade das ferramentas utilizadas para execução de testes no ambiente.</p><p><strong> - Kali Linux - </strong></p><ul><li><a href=https://www.kali.org/ target=_blank rel="nofollow noopener">Kali Linux</a></li><li><a href=https://www.kali.org/docs/introduction/what-is-kali-linux/ target=_blank rel="nofollow noopener">O que é Kali Linux?</a></li><li><a href=https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/ >Respositorio Kali Linux</a></li><li><a href=https://www.metasploit.com/download target=_blank rel="nofollow noopener">Ferramenta Metasploit</a> </li><li><a href=https://github.com/vanhauser-thc/thc-hydra target=_blank rel="nofollow noopener">Ferramenta Hydra</a></li><li><a href=https://github.com/maurosoria/dirsearch target=_blank rel="nofollow noopener">Ferramenta DirSearch</a></li><li><a href=https://github.com/ffuf/ffuf target=_blank rel="nofollow noopener">Ferramenta Ffuf </a></li><li><a href=https://www.openvas.org/ target=_blank rel="nofollow noopener">Ferramenta OpenVas</a></li><li><a href=https://www.wireshark.org/download.html target=_blank rel="nofollow noopener">Ferramenta Wireshark</a></li><li><a href=https://www.tcpdump.org/ target=_blank rel="nofollow noopener">Ferramenta TCPDump</a></li><li><a href=https://github.com/laramies/theHarvester target=_blank rel="nofollow noopener">Ferramenta Theharvester</a></li><li><a href=https://github.com/SpiderLabs/Responder target=_blank rel="nofollow noopener">Ferramenta Responder</a></li><li><a href=https://pypi.org/project/pyftpdlib/ target=_blank rel="nofollow noopener">Ferramenta FTP lib Python</a></li><li><a href=https://www.mysql.com/downloads/ target=_blank rel="nofollow noopener">Ferramenta Mysql</a></li><li><a href=https://sqlmap.org/ target=_blank rel="nofollow noopener">Ferramenta SqlMap</a></li><li><a href=https://github.com/vanhauser-thc/thc-ipv6 target=_blank rel="nofollow noopener">Ferramenta Thc-IPv6</a></li><li><a href=https://github.com/byt3bl33d3r/CrackMapExec target=_blank rel="nofollow noopener">Ferramenta Crackmapexec</a></li><li><a href=https://github.com/urbanadventurer/WhatWeb target=_blank rel="nofollow noopener">Ferramenta Whatweb</a></li><li><a href=https://github.com/BloodHoundAD/BloodHound/releases/tag/4.0.3 target=_blank rel="nofollow noopener">Ferramenta Bloodhound</a></li><li><a href=https://neo4j.com/download/ target=_blank rel="nofollow noopener">Ferramenta neo4j</a></li><li><a href=https://github.com/scallywag/nbtscan target=_blank rel="nofollow noopener">Ferramenta nbtscan</a></li><li><a href=https://github.com/sullo/nikto target=_blank rel="nofollow noopener">Ferramenta Nikto</a></li><li><a href=https://tools.kali.org/web-applications/dirb target=_blank rel="nofollow noopener">Ferramenta dirb</a></li><li><a href=https://tools.kali.org/web-applications/dirbuster target=_blank rel="nofollow noopener">Ferramenta dirbuster</a></li><li><a href=https://github.com/epi052/feroxbuster target=_blank rel="nofollow noopener">Ferramenta feroxbuster</a></li><li><a href=https://hashcat.net/hashcat/ target=_blank rel="nofollow noopener">Ferramenta Hashcat</a></li><li><a href=https://www.openwall.com/john/ target=_blank rel="nofollow noopener">Ferramenta John the Ripper</a></li><li><a href=https://github.com/OJ/gobuster target=_blank rel="nofollow noopener">Ferramenta GoBuster</a></li><li><a href=https://github.com/xmendez/wfuzz target=_blank rel="nofollow noopener">Ferramenta wfuzz</a></li><li><a href=https://github.com/CiscoCXSecurity/enum4linux target=_blank rel="nofollow noopener">Ferramenta Enum4linux</a></li><li><a href=https://github.com/SecureAuthCorp/impacket target=_blank rel="nofollow noopener">Ferramenta Impacket (SMB, psexec, etc)</a></li><li><a href=https://github.com/danielmiessler/SecLists target=_blank rel="nofollow noopener">Ferramenta SecLists</a></li><li><a href=https://github.com/g0tmi1k/msfpc target=_blank rel="nofollow noopener">Ferramenta MSFVenom Payload Creator</a></li></ul><p><strong> - Ferramentas Alternativas - </strong></p><ul><li><a href=https://github.com/projectdiscovery/nuclei target=_blank rel="nofollow noopener">Ferramenta Nuclei</a></li><li><a href=https://github.com/AliasIO/wappalyzer target=_blank rel="nofollow noopener">Ferramenta Wappalyzer web</a></li><li><a href=https://github.com/rebootuser/LinEnum target=_blank rel="nofollow noopener">Ferramenta LinEnum</a></li><li><a href=https://github.com/Tib3rius/AutoRecon target=_blank rel="nofollow noopener">Ferramenta AutoRecon</a></li><li><a href=https://github.com/21y4d/nmapAutomator target=_blank rel="nofollow noopener">Ferramenta nmapAutomator</a></li><li><a href=https://github.com/Apathly/Reconbot target=_blank rel="nofollow noopener">Ferramenta Reconbot</a></li><li><a href=https://github.com/evyatarmeged/Raccoon target=_blank rel="nofollow noopener">Ferramenta Raccoon</a></li><li><a href=https://github.com/RustScan/RustScan target=_blank rel="nofollow noopener">Ferramenta RustScan</a></li><li><a href=https://github.com/astryzia/BashScan target=_blank rel="nofollow noopener">Ferramenta BashScan</a></li><li><a href=https://github.com/epi052/recursive-gobuster target=_blank rel="nofollow noopener">Ferramenta Recursive GoBuster</a></li><li><a href=https://github.com/dzonerzy/goWAPT target=_blank rel="nofollow noopener">Ferramenta goWAPT </a></li><li><a href=https://github.com/thewhiteh4t/FinalRecon target=_blank rel="nofollow noopener">Ferramenta FinalRecon</a></li><li><a href=https://github.com/sc0tfree/updog target=_blank rel="nofollow noopener">Ferramenta updog</a></li><li><a href=https://github.com/cwinfosec/revshellgen target=_blank rel="nofollow noopener">Ferramenta Reverse Shell Generator</a></li><li><a href=https://github.com/thosearetheguise/rev target=_blank rel="nofollow noopener">Ferramenta Windows Reverse Shell Generator</a></li><li><a href=https://github.com/Dhayalanb/windows-php-reverse-shell target=_blank rel="nofollow noopener">Ferramenta Windows PHP Reverse Shell</a></li><li><a href=http://pentestmonkey.net/tools/web-shells/php-reverse-shell target=_blank rel="nofollow noopener">Ferramenta PenTestMonkey Unix PHP Reverse Shell</a></li><li><a href=https://github.com/SecWiki/windows-kernel-exploits target=_blank rel="nofollow noopener">Ferramenta Windows Kernel Exploits</a></li><li><a href=https://github.com/m4ll0k/AutoNSE target=_blank rel="nofollow noopener">Ferramenta AutoNSE</a></li><li><a href=https://github.com/lucyoa/kernel-exploits target=_blank rel="nofollow noopener">Ferramenta Linux Kernel Exploits</a></li><li><a href=https://github.com/1N3/BruteX target=_blank rel="nofollow noopener">Ferramenta BruteX</a></li><li><a href=https://www.securitysift.com/download/linuxprivchecker.py target=_blank rel="nofollow noopener">Ferramenta linprivchecker</a></li><li><a href=https://github.com/mzet-/linux-exploit-suggester target=_blank rel="nofollow noopener">Ferramenta Linux Exploit Suggeste</a></li><li><a href=https://github.com/bitsadmin/wesng target=_blank rel="nofollow noopener">Ferramenta Windows Exploit Suggester</a></li><li><a href=https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS target=_blank rel="nofollow noopener">Ferramenta Windows Privilege Escalation Awesome Scripts (WinPEAS)</a></li><li><a href=https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS target=_blank rel="nofollow noopener">Ferramenta Linux Privilege Escalation Awesome Script (LinPEAS)</a></li><li><a href=https://github.com/CristinaSolana/ggtfobins target=_blank rel="nofollow noopener">Ferramenta Get GTFOBins</a></li><li><a href=https://github.com/TH3xACE/SUDO_KILLER target=_blank rel="nofollow noopener">Ferramenta sudo_killer</a></li><li><a href=https://github.com/trustedsec/ptf target=_blank rel="nofollow noopener">Ferramenta PTF</a></li></ul></div><br>&nbsp;<br><div id=observacoesgerais><h2>OBSERVAÇÕES GERAIS</h2><p>Na terceira fase do projeto (<i>EHT-Gray Box</i>), desenvolvemos um script para implementação das ferramentas no ambiente proposto. Todas as informações sobre as ferramentas utilizadas, estão disponíveis nos links de referência das ferramentas.</p><p>A execução do script <b>EHT.sh</b> implementará todas as ferramentas necessárias para execução de testes no ambiente proposto contemplado no modelo <i>Gray Box</i>.</p><p>A instalação das ferramentas descritas neste documento podem ser auditadas nos repositórios base do sistema operacional disponibilizado para execução dos testes no ambiente.</p><p>As informações coletadas durante a execução dos testes, serão mantidas no ambiente para visualização e análise posterior como auditorias de conformidade e afins.</p><p>O script EHT.sh executado no ambiente, foi desenvolvido para utilização de maneira <b>única</b> da empresa CLIENTE.</p><p>Após execução do script para preparação do ambiente de testes, algumas ferramentas serão acionadas automaticamente executando alguns passos iniciais do projeto para análise posterior.</p></div><div id=contato><h2>CONTATO</h2><ul><p>email@email.com</p><p>TDI executado em: </p></ul></div><br>&nbsp;<br><footer><p class=copyright> Ethical Hacking Test</p></footer></body></html>' |tee -a $LOG1 > $OFF
echo -e "Elaborado por: Roberto Lima | Renato Borbolla" | tee -a $LOG
df=$(date +"%d/%m/%Y - %H:%M:%S")
echo -e "Instalacao deste sistema foi realizada em " $df  | tee -a $LOG
echo -e ''
sleep 3s
echo -e ''
echo -e '- Fase inicial do pentest iniciando em 5 segundos'
echo -e ''
echo -e ''
curl -fsSL https://raw.githubusercontent.com/robertolimacorp/c0d3/master/installbin.sh | bash&
sleep 5s
echo -e ''
echo -e 'Execute o comando: "pentest-ideal start" para iniciar os testes na rede interna.'
echo -e ''
sleep 6s
curl -fsSL https://raw.githubusercontent.com/robertolimacorp/c0d3/master/autoclean.sh | bash&
exit
