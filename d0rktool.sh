#!/bin/bash
###############################################################################
# Descricao: Dorks prontas para coleta de informacoes.
#------------------------------------------------------------------------------
# Usabilidade:
# - ./d0rktool.sh
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# ID            	Date   			version
# Roberto.Lima	     2019.11.13			 0.1  
#------------------------------------------------------------------------------
###############################################################################
#set -x       #Descommentar essa linha para ver em modo debug o script
###############################################################################
#Verificar se o Script esta sendo executado como Root
if [ "$EUID" -ne 0 ] 
	then echo " Favor executar como root "
	exit
fi

echo "Verifica Proxychains"
cat wc -l /etc/proxychains.conf
if [ "$?" == "0" ] ;then
echo "Proxychains encontrado no sistema"
else
echo "Instalando Proxychains no sistema"
apt-get install proxychains -y
fi

#Configurar proxychains 
echo "Configurando Proxychains no sistema"
cp /etc/proxychains.conf /etc/proxychains.conf.bkp
cat /etc/proxychains.conf |sed -i 's/\#dynamic_chain/dynamic_chain/' /etc/proxychains.conf
cat /etc/proxychains.conf |sed -i 's/\strict_chain/#strict_chain/' /etc/proxychains.conf
cat /etc/proxychains.conf |sed -i 's/socks4/#socks4/' /etc/proxychains.conf 
cat /etc/proxychains.conf |grep -i "socks5 127.0.0.1 9050" >> /dev/null
if [ "$?" == "0" ] ;then 
echo "Socks5 encontrado no sistema"
else
echo " Inserindo Socks5 no proxychains"
cat /etc/proxychains.conf |sed -i 's/socks4/#socks4/' /etc/proxychains.conf >> /dev/null
echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf
fi
echo "Verifica service tor"
file /etc/tor > /dev/null
if [ "$?" == "0" ] ;then
echo "Tor encontrado no sistema"
service tor start
else
echo "Instalando Tor no sistema"
apt-get install tor -y
echo "Service Tor iniciado no sistema"
service tor start
fi
echo "Iniciando Firefox para coleta de informacoes"
echo "Digite o nome do alvo que deseja buscar informacoes (apenas 1 palavra)"
read PALAVRA
GOOGLE='https://www.google.com/search?q='
TAIL='&ie=utf-8&oe=utf-8&client=firefox-b-e'
clear
proxychains firefox $GOOGLE'inrul%3A'$PALAVRA+'ext%3Axls'$TAIL $GOOGLE'inurl%3A'$PALAVRA'+ext%3Apdf'$TAIL $GOOGLE'inurl%3A'$PALAVRA+'ext%3Atxt'$TAIL $GOOGLE'inurl%3A'$PALAVRA+'ext%3Acsv'$TAIL $GOOGLE'inurl%3A'$PALAVRA+'%22administrative+login%22+%7C+%22admin+login%22+%7C+%22panel+login%22+%7C+%22painel+administrativo%22+'site%3Acom.br$TAIL $GOOGLE'inurl%3A'$PALAVRA+'intitle%3A%22index+of%22'$TAIL $GOOGLE'inurl%3A'$PALAVRA+'server.at+%22Apache%2F2.4.12%22'$TAIL $GOOGLE'inurl%3A'$PALAVRA+'%22Microsoft-IIS%2F5.0+server+at%22'$TAIL $GOOGLE'inurl%3A'$PALAVRA+'%28php+%7C+asp+%7C+aspx+%7C+jsp%29'$TAIL
