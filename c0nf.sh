#!/bin/sh
### BEGIN INIT INFO
# Provides:          c0nf.sh
# Required-Start:    $local_fs $remote_fs $network $syslog
# Required-Stop:     $local_fs $remote_fs $network $syslog
# Default-Start:     2 3 5  
# Default-Stop:      0 1 6  
# Short-Description: Start c0nf.sh at boot time
# Description:       Executar configuracoes personalizadas.
### END INIT INFO

sh /root/c0nf.sh

exit



#Criar script com ações desejadas após boot e salvar em rc.local (/root/c0nf.sh)

    #echo America/Sao_Paulo > /etc/timezone
    #timedatectl set-timezone America/Sao_Paulo
    #export TZ=America/Sao_Paulo
    #setxkbmap -model abnt2 br
    #service ssh start 
    #service tor start
    #chmod 600 /boot/* |ls -l /boot/

