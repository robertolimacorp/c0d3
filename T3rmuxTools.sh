#!/bin/bash
###############################################################################
# Descricao: Script Utilidades Termux - Android Linux.
#------------------------------------------------------------------------------
# Usabilidade:
# - ./T3rmuxTools.sh
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# ID            	Date   			version
# Roberto.Lima	     2019.11.06			 0.1  
#------------------------------------------------------------------------------
###############################################################################
#set -x       #Descommentar essa linha para ver em modo debug o script
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
NC='\033[0m'

echo -e ${NC}${YELLOW}""
echo -e "Apertando volume up + q mostra as teclas (Esc, TAB, CRTL, ALT, as setas, END, HOME, PG UP e DWN)"
echo -e ""${NC}${WHITE}
echo -e " --> Instalando utilitáios do sistema  -  " "["${NC}${GREEN}✔${NC}${WHITE}"]"

apt update && apt upgrade -y && pkg install screenfetch man nano wget python python2 -y

echo -e " --> Instalando Arsenal Magico -  " "["${NC}${GREEN}✔${NC}${WHITE}"]"
pkg install curl
pkg install nmap
pkg install tcpdump


