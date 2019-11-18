#!/bin/bash
###############################################################################
# Descricao: Script Utilidades Kali Linux.
#------------------------------------------------------------------------------
# Usabilidade:
# - ./1nit.sh
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# ID            	Date   			version
# Roberto.Lima  2019.11.04			 1.0  
#------------------------------------------------------------------------------
###############################################################################
#set -x       #Descommentar essa linha para ver em modo debug o script
###############################################################################
clear
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
LOG=/root/Desktop/$HOST-$DATA.txt
touch $LOG

#Verificar se o Script esta sendo executado como Root
if [ "$EUID" -ne 0 ] 
	then echo " Favor executar como root " $FAIL >> $LOG
	exit
fi

clear
echo -e ${NC}${YELLOW}""
echo  -e "========== ...Iniciando configuracao do sistema ... ================="
uname -a >> $LOG
echo -e "----------------------------------------------------------------------" >>$LOG

#Atualizar o sistema
echo "Deseja atualizar o sistema Update e Upgrade? Sim ou Não [S/n]"
read RESP
if [ "$RESP" == "S" ]; then
echo "Atualizando o sistema" $OK >> $LOG
apt-get install update && apt-get install upgrade -y
else 
echo "Atualizacao cancelada pelo usuario" $FAIL >> $LOG
fi
#Configurar teclado ABNT2
echo "Teclado configurando ABNT2" $OK >> $LOG
setxkbmap -model abnt2 -layout br 

#Exportar timezone 
echo "Timezone America Sao Paulo" $OK >> $LOG
timedatectl set-timezone America/Sao_Paulo
export TZ=America/Sao_Paulo

#instalar NTP
echo "Instalar NTP" $OK >> $LOG
apt-get install ntp
apt-get install ntpdate
ntpdate pool.ntp.br

#instalar terminator
cat /usr/bin/terminator | head -n 3 > $OFF
if [ "$?" == "0" ] ;then 
echo "Terminator encontrado no sistema" $OK >> $LOG
else
echo "Instalando terminator no sistema" $FAIL >> $LOG
apt-get install terminator -y
fi

#Proxychains 
cat /etc/proxychains* | head -n 3 >> $OFF
if [ "$?" == "0" ] ;then 
cp /etc/proxychains.conf /etc/proxychains.conf.bkp$DATA
echo "Proxychains encontrado no sistema" $OK >> $LOG
else
echo "Instalando Proxychais no sistema" $FAIL >> $LOG
apt-get install proxychains -y
echo "Proxychains instalado no sistema" $OK >> $LOG
fi

#Configurar proxychains 
echo "Configurando Proxychains no sistema" $OK >> $LOG
cat /etc/proxychains.conf |sed -i 's/\#dynamic_chain/dynamic_chain/' /etc/proxychains.conf
cat /etc/proxychains.conf |sed -i 's/\strict_chain/#strict_chain/' /etc/proxychains.conf
cat /etc/proxychains.conf |sed -i 's/socks4/#socks4/' /etc/proxychains.conf >> $OFF
cat /etc/proxychains.conf |grep -i "socks5 127.0.0.1 9050"
if [ "$?" == "0" ] ;then 
echo "Socks5 encontrado no sistema" $OK >> $LOG
else
echo " Inserindo Socks5 no proxychains" $OK >> $LOG 
cat /etc/proxychains.conf |sed -i 's/socks4/#socks4/' /etc/proxychains.conf >> $OFF
echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf	
fi

#Valida diretorio tor
echo "Verifica servico tor" 
file /etc/tor > $OFF
if [ "$?" == "0" ] ;then 
echo "Tor encontrado no sistema" $OK >> $LOG
service tor start
else
echo "Instalando Tor no sistema"
apt-get install tor -y
echo "Servico Tor iniciado no sistema" $OK >> $LOG
service tor start
fi

#Instalar Tor Browser
updatedb | locate -b "tor-browser" > $OFF
if [ "$?" == "0" ]; then
echo "Tor Browser localizado no sistema"  $OK >> $LOG
else
echo "Instalando Tor Browser no Sistema" $OK >> $LOG
cd /opt
wget https://www.torproject.org/dist/torbrowser/9.0/tor-browser-linux64-9.0_en-US.tar.xz 
tar -xvf tor-browser-linux64-9.0_en-US.tar.xz
rm -f tor-browser-linux64-9.0_en-US.tar.xz
mv tor-browser_en-US/ tor-browser/
echo "Tor Browser instalado com sucesso" $OK >> $LOG
fi

#instalação de tools
clear
echo "Instalando Arsenal no sistema" $OK >> $LOG
echo -e "----------------------------------------------------------------------" >>$LOG
echo "Aguarde alguns instantes..."
cd /opt/
echo "--->Arachni" $OK >> $LOG
git clone https://github.com/Arachni/arachni.git
echo "--->Zirikatu" $OK >> $LOG
git clone https://github.com/pasahitz/zirikatu.git
echo "--->SpiderFoot" $OK >> $LOG
git clone https://github.com/smicallef/spiderfoot.git
echo "--->Sn1per" $OK >> $LOG
git clone https://github.com/1N3/Sn1per.git
echo "--->Dnsrebind Toolkit" $OK >> $LOG
git clone https://github.com/brannondorsey/dns-rebind-toolkit.git
echo "--->OWASP - Amass" $OK >> $LOG
git clone https://github.com/OWASP/Amass.git
echo "--->Aquatone" $OK >> $LOG
git clone https://github.com/michenriksen/aquatone.git
echo "--->WhatBreach" $OK >> $LOG
git clone https://github.com/Ekultek/WhatBreach.git
echo "--->InstagramOSINT" $OK >> $LOG
git clone https://github.com/sc1341/InstagramOSINT.git
echo "--->Cr3d0v3r" $OK >> $LOG
git clone https://github.com/D4Vinci/Cr3dOv3r.git
echo "--->ScannerINURL" $OK >> $LOG
git clone https://github.com/googleinurl/SCANNER-INURLBR.git
echo "--->DotDotPWN" $OK >> $LOG
git clone https://github.com/wireghoul/dotdotpwn.git
echo "--->GoPhish" $OK >> $LOG
git clone https://github.com/gophish/gophish.git
echo "--->Wifiphisher" $OK >> $LOG
git clone https://github.com/wifiphisher/wifiphisher.git
echo "--->PowerShell Empire" $OK >> $LOG
git clone https://github.com/EmpireProject/Empire.git
echo "--->Mimikatz" $OK >> $LOG
git clone https://github.com/gentilkiwi/mimikatz.git
echo "--->Diretorio de payloads (/opt/payloads) " $OK >> $LOG
mkdir -p /opt/payloads
echo "--->Download de payloads" $OK >> $LOG
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/dir_brute.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/js_inject.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/ldap_injection.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/list.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/passive_sqli.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/password_brute.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/path_traversal.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/path_traversal_win32.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/proxy_list.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/sqli.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/xpath_injection.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/xss.txt
wget https://github.com/CoolerVoid/0d1n/blob/master/payloads/xss_robertux.txt
wget https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/shubs-stackoverflow.txt
mv /opt/*.txt /opt/payloads
ls /opt/payloads/ |cut -d: -f2 >> $LOG
echo "--->Od1n Payloads" $OK >> $LOG
wc -l /opt/payloads/dir_brute.txt js_inject.txt shubs-stackoverflow.txt ldap_injection.txt list.txt passive_sqli.txt password_brute.txt path_traversal.txt path_traversal_win32.txt proxy_list.txt sqli.txt xpath_injection.txt xss.txt xss_robertux.txt
if [ "$?" == "0" ] ;then 
echo "payloads no diretorio do sistema (/opt/payloads)" $OK >> $LOG
else
echo "erro nos payloads do sistema" $FAIL >> $LOG
fi

#Pentest Mobile
echo  "--->MobSF - Mobile" $OK >> $LOG
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
clear
echo "Instalacao do Arsenal ok"
echo "Iniciando Hardening do sistema" $OK >> $LOG
echo -e "----------------------------------------------------------------------" >>$LOG

#instalar rkhunter e efetuar a primeira checagem
cat /etc/rkhunter* |head -n 3 >> $OFF
if [ "$?" == "0" ]; then 
echo "rkhunter encontrado no sistema" $OK >> $LOG
rkhunter --update
rkhunter --propupd
rkhunter --check --skip-keypress --report-warnings-only
else 
echo "Rkhunter nao encontrado" $FAIL >> $LOG
echo "Instalando rkhunter no sistema e efetuando checagem" $OK >> $LOG
apt-get install rkhunter -y
rkhunter --update
rkhunter --propupd
rkhunter --check --skip-keypress --report-warnings-only
echo "Rkhunter instalado com sucesso" $OK >> $LOG
fi

#instalar fail2ban
echo "instalar fail2ban" $OK >> $LOG
apt-get install fail2ban -y
echo "Efetuando backup do arquivo sysctl.conf"
cp /etc/sysctl.conf /etc/sysctl.conf.bkp.$DATA

#Desabilita Ipv6 Temporario 
echo "Desabilitar Ipv6 temporariamente" $OK >> $LOG
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1

#Desabilitar Ipv6 permanente descomente as linhas a seguir;
#echo "Desabilitar Ipv6 Permanente" $OK >> $LOG
#echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.conf
#echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.conf
#echo "net.ipv6.conf.lo.disable_ipv6=1" >> /etc/sysctl.conf
#sysctl -p

echo "Seguranca do Kernel"  $OK >> $LOG
echo "Configuracao /etc/sysctl.conf" $OK >> $LOG
echo "#=============Nova Configuracao sysctl.conf=============" > /etc/sysctl.conf 
echo "Hardening Anti DoS"  
echo "Protecao contra SYN Flood (SYN cookies)"  $OK >> $LOG
echo "net.ipv4.tcp_syncookies=1" >> $SYS
echo  >> $SYS
echo "Duração do status do TCP FIN-WAIT-2 (15 seg)" $OK >> $LOG
echo "net.ipv4.tcp_fin_timeout=15" >> $SYS
echo  >> $SYS
echo "# Comprimento da fila SYN (8192)">> $SYS
echo "net.ipv4.tcp_max_syn_backlog = 8192" >> $SYS
echo  >> $SYS
echo "# Aumentam os limites do buffer TCP de ajuste automático do Linux" >> $SYS
echo "net.core.netdev_max_backlog = 16384" >> $SYS
echo  >> $SYS
echo "# Aumentar o número de conexões de entrada" >> $SYS
echo "net.core.somaxconn = 4096" >> $SYS
echo  >> $SYS
echo "# Aumenta o tamanho do pool de buckets tcp-time-wait para evitar ataques simples do DOS" >> $SYS
echo "net.ipv4.tcp_max_tw_buckets = 65535" >> $SYS
echo "net.ipv4.tcp_tw_reuse = 1"  >> $SYS
echo "net.ipv4.tcp_tw_recycle = 1" >> $SYS
echo  >> $SYS
echo "# Diminue o valor padrão de tempo para que as conexões continuem ativas" >> $SYS
echo "net.ipv4.tcp_keepalive_time = 300" >> $SYS
echo "net.ipv4.tcp_keepalive_probes = 3" >> $SYS
echo  >> $SYS
echo "# Reduz retransmissao SYN + ACK (3)" >> $SYS
echo "net.ipv4.tcp_syn_retries = 3" >> $SYS
echo "net.ipv4.tcp_synack_retries = 3 " >> $SYS
echo  >> $SYS
echo "# o valor maior do TCP ORPHAN impediria ataques simples de DoS" >> $SYS
echo "net.ipv4.tcp_max_orphans = 65536" >> $SYS
echo  >> $SYS
echo "# Quantas páginas (4KB cada página em x86) podem ser usadas na conexão TCP" >> $SYS
echo "net.ipv4.tcp_mem = 131072 196608 262144" >> $SYS
echo  >> $SYS
echo "# Buffer de recebimento máximo de sockt" >> $SYS
echo "net.core.rmem_max = 67108864" >> $SYS
echo  >> $SYS
echo "# Buffer de envio máximo de socket" >> $SYS
echo "net.core.wmem_max = 67108864" >> $SYS
echo  >> $SYS
echo "# Aumentar o espaço do buffer de leitura alocável" >> $SYS
echo "net.ipv4.tcp_rmem = 4096 8192 16777216" >> $SYS
echo  >> $SYS
echo "# Aumente o espaço de buffer de gravação alocável" >> $SYS
echo "net.ipv4.tcp_wmem = 4096 8192 16777216" >> $SYS
echo  >> $SYS
echo "############### Início da rede IPv4 ############### " >> $SYS
echo "# Não aceita o roteamento de origem" >> $SYS
echo "net.ipv4.conf.all.accept_source_route = 0" >> $SYS
echo  >> $SYS
echo "# Aceitar redirecionamentos? Não, este não é o roteador" >> $SYS
echo "net.ipv4.conf.all.accept_redirects = 0" >> $SYS
echo  >> $SYS
echo "# Nao é router Portanto, nenhum roteamento permitido" >> $SYS
echo "net.ipv4.conf.all.send_redirects = 0" >> $SYS
echo "net.ipv4.conf.default.send_redirects = 0" >> $SYS
echo  >> $SYS
echo "# Para ignorar todo o pacote ICMP (1)" >> $SYS
echo "net.ipv4.icmp_echo_ignore_all = 1" >> $SYS
echo  >> $SYS
echo "# Ignorar tudo ICMP ECHO e solicitações TIMESTAMP enviadas a ele por broadcast / multicast " >> $SYS
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> $SYS
echo  >> $SYS
echo "# Ignorar erros de ICMP" >> $SYS
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> $SYS
echo  >> $SYS
echo "# Não permite ao usuário ler tabelas de símbolos de endereço do kernel" >> $SYS
echo "kernel.kptr_restrict=1" >> $SYS
echo  >> $SYS
echo "# As informações do dmesg podem ser lidas somente pelo root" >> $SYS
echo "kernel.dmesg_restrict=1" >> $SYS
echo  >> $SYS
echo "# Minimo mapa de memoria é de 65536" >> $SYS
echo "vm.mmap_min_addr=65536" >> $SYS
echo  >> $SYS
echo "# Apenas o root pode debugar ( com CAP_SYS_PTRACE )" >> $SYS
echo "kernel.yama.ptrace_scope = 2" >> $SYS
echo  >> $SYS
echo "# Permite mais PIDs " >> $SYS
echo "kernel.pid_max=65536" >> $SYS
echo  >> $SYS
echo "# Ativa o ExecShield" >> $SYS
echo "kernel.exec-shield=2" >> $SYS
echo  >> $SYS
echo "# Correcao RFC 1337 " >> $SYS
echo "net.ipv4.tcp_rfc1337=1" >> $SYS
echo  >> $SYS
echo "# mmap base, heap, stack e VDSO sao randomizados" >> $SYS
echo "# Mitigar exploit" >> $SYS
echo "kernel.randomize_va_space=2" >> $SYS
echo  >> $SYS
echo "# Ativar validação de fonte por caminho reverso, conforme especificado em RFC1812" >> $SYS
echo "net.ipv4.conf.all.rp_filter=1" >> $SYS
echo  >> $SYS
echo "# Ignorar erros de ICMP incorretos" >> $SYS
echo "net.ipv4.icmp_ignore_bogus_error_messages=1" >> $SYS
echo  >> $SYS
echo "# Registrar pacotes com endereços impossíveis no log do kernel" >> $SYS
echo "net.ipv4.conf.all.log_martians=1" >> $SYS
echo  >> $SYS
echo "# Protege contra criacao ou seguir links " >> $SYS
echo "fs.protected_hardlinks=1 " >> $SYS
echo "fs.protected_symlinks=1" >> $SYS

#Alterar arquivo sshd_config (/etc/ssh/sshd_config)
echo "Alterando configuracoes do arquivo sshd_config" $OK >> $LOG
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bkp$DATA
echo "backup do arquivo sshd_config efetuado com sucesso" $OK >> $LOG
echo "alterando porta padrao ssh para 2220" $OK >> $LOG
#cat /etc/ssh/sshd_config |sed -i 's/Port 22/Port 2220/' /etc/ssh/sshd_config
cat /etc/ssh/sshd_config |sed -i 's/\#IgnoreRhosts yes/IgnoreRhosts yes/' /etc/ssh/sshd_config
cat /etc/ssh/sshd_config |sed -i 's/\#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config 
cat /etc/ssh/sshd_config |sed -i 's/\#MaxAuthTries*/MaxAuthTries 5/'/etc/ssh/sshd_config
#cat /etc/ssh/sshd_config |sed -i 's/\#PermitRootLogin yes/PermitRootLogin no/'/etc/ssh/sshd_config
#cat /etc/ssh/sshd_config sed -i 's/\#PubkeyAuthentication yes/PubkeyAuthentication no/'/etc/ssh/sshd_config
cat /etc/ssh/sshd_config |sed -i 's/X11Forwarding yes/X11Forwarding no/sshd_config'/etc/ssh/sshd_config

echo "alterar arquivo ssh_config" 
cp /etc/ssh/ssh_config /etc/ssh/ssh_config.bkp$DATA
echo "efetuando backup arquivo ssh_config"
cat /etc/ssh/ssh_config |sed -i 's/   HashKnownHosts*|HashKnownHosts yes/' /etc/ssh/ssh_config
cat /etc/ssh/ssh_config |sed -i 's/\#   ForwardX11 no/ForwardX11 no/' /etc/ssh/ssh_config
cat /etc/ssh/ssh_config |sed -i 's/\#   Port 22/Port 22/' /etc/ssh/ssh_config

echo "Alterar permissao no diretorio /boot (600)" $OK >> $LOG
#Padrao 644 nos arquivos e 755 no grub
chmod 600 /boot/* |ls -l /boot/
echo -e "----------------------------------------------------------------------" >>$LOG
echo "Listar senhas expiradas" $OK >> $LOG
cat /etc/shadow | cut -d: -f 1,2 | grep '!' >>  $LOG
echo -e "----------------------------------------------------------------------" >>$LOG
echo "lista usuarios disponiveis" >> $LOG
egrep -v '.*:\*|:\!' /etc/shadow | awk -F: '{print $1}'  >> $LOG
echo -e "----------------------------------------------------------------------" >>$LOG
echo "Lista de usuários root ou id 0" >> $LOG
awk -F: '($3 == "0") {print}' /etc/passwd >> $LOG
echo -e "----------------------------------------------------------------------" >>$LOG
echo "Procurando senhas em branco" $OK >> $LOG
cat /etc/shadow |awk -F: '($2==""){print $1}'  >> $LOG
echo -e "----------------------------------------------------------------------" >>$LOG
#Iptables e regras de hardening
echo "Aplicar regras Iptables Hardening"  $OK >> $LOG
iptables -F #limpa regras
#iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT #previne DoS Local
#iptables -A INPUT -p icmp -j REJECT --reject-with  icmp-host-unreachable #responde ICMP com host unreachable

echo "Protecao contra SYN Flood " $OK >> $LOG
#iptables -t raw -A PREROUTING -i eth0 -p tcp --dport 80 --syn -j NOTRACK
#iptables -A INPUT -i eth0 -p tcp --dport 80 -m state UNTRACKED,INVALID  -j SYNPROXY --sack-perm --timestamp --mss 1480 --wscale 7 --ecn

echo "Liberando conexoes estabelecidas" $OK >> $LOG
#iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
#iptables -A FORWARD -m state --state RELATED,ESTABLISHED,NEW -j ACCEPT
#iptables -A OUTPUT -m state --state RELATED,ESTABLISHED,NEW -j ACCEPT
#iptables -A INPUT -i lo -j ACCEPT

echo "Fechando portas indesejadas" $OK >> $LOG
#iptables -A INPUT -p tcp --dport PORT_NUMBER -j DROP

echo "Regras iptables aplicadas com sucesso" $OK >> $LOG
echo "Deseja iniciar as atividades de busca? Sim ou não [S/n]"
read YEP
if [ "$YEP" == "S" ]; then
clear
echo "Iniciando Firefox para coleta de informacoes"
echo "Digite o nome do alvo que deseja bucar informacoes (apenas 1 palavra)"
read PALAVRA
GOOGLE='https://www.google.com/search?q='
TAIL='&ie=utf-8&oe=utf-8&client=firefox-b-e'
clear
proxychains firefox $GOOGLE'inrul%3A'$PALAVRA+'ext%3A'xls$TAIL $GOOGLE'inurl%3A'$PALAVRA+'ext%3A'pdf$TAIL $GOOGLE'inurl%3A'$PALAVRA+'ext%3A'txt+-robots.txt$TAIL $GOOGLE'inurl%3A'$PALAVRA+'ext%3A'csv$TAIL $GOOGLE'inurl%3A'$PALAVRA+'%22administrative+login%22+%7C+%22admin+login%22+%7C+%22panel+login%22+%7C+%22painel+administrativo%22+site%3Acom.br'$TAIL $GOOGLE'inurl%3A'$PALAVRA+'intitle%3A%22index+of%22'$TAIL $GOOGLE'inurl%3A'$PALAVRA+'server.at+%22Apache%2F2.4.12%22'$TAIL $GOOGLE'inurl%3A'$PALAVRA+'%22Microsoft-IIS%2F5.0+server+at%22'$TAIL $GOOGLE'inurl%3A'$PALAVRA+'%28php+%7C+asp+%7C+aspx+%7C+jsp%29'$TAIL 

#Para iniciar todos os buscadores basta descomentar a linha abaixo
#firefox https://www.shodan.io/ https://censys.io/ https://fofa.so/ https://app.binaryedge.io/login https://www.onyphe.io/ https://ghostproject.fr/ https://wigle.net/index https://hunter.io/ https://www.zoomeye.org/ https://www.netdb.io/ https://www.google.com/ https://www.bing.com/

else 
clear 
echo " Sistema pronto para utilizacao!!!"
echo -e "======================================================================" >>$LOG
echo "Fim da instalacao dos utiliarios do sistema" $OK >> $LOG
fi
