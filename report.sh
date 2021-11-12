#/bin/bash

HOST=`hostname`
DATA=`date +"%d%m%Y-%H%M"`

LOG='/tmp/index.html'
E='<p><input type="Button" style="width:100px; height:30px; border-radius: 10px; font-family: verdana; background-color: #F7C510" value="IGNORADO">'
F='<p><input type="Button" style="width:100px; height:30px; border-radius: 10px; font-family: verdana; background-color: #C40001;" value="FALHOU">'
P='<p><input type="Button" style="width:100px; height:30px; border-radius: 10px; font-family: verdana; background-color: #137624;" value="OK">'
#criar aquivo de Log para análise de ambiente
touch $LOG
######################################### 
echo "<!DOCTYPE html><html lang="pt-br"><head><title>EHT - Gray Box 2021</title><meta charset="utf-8"></head><body><h1>Benchmark Linux | Linux</h1><h2>Este relatório está em conformidade com o NONONONON<h2><h3>Os controles inseridos são:</h3><div>" >>$LOG
CONTROL="1.1.PING"
ping -c 1 localhost
if [ "$?" == "0" ]; then
 echo "$P""$CONTROL">> $LOG
else 
 echo "$P""$CONTROL">> $LOG
fi
#==============================
CONTROL="1.2 LOCALHOST"
ping -c 1 localhost
if [ "$?" == "0" ]; then
 echo "$P""$CONTROL">> $LOG
else 
 echo "$P""$CONTROL">> $LOG
fi
#==============================
CONTROL="1.3.IPCONFIG"
ipconfigd
if [ "$?" == "0" ]; then
 echo "$P" "$CONTROL">> $LOG
else 
 echo "$F" "$CONTROL">> $LOG
fi
#==============================
CONTROL="1.5.HOSTNAME"
hostname
 echo "$E" "$CONTROL">> $LOG
echo "<p>Elaborado por: Roberto Lima | MoL-PS" >> $LOG
echo "</div></body></html>">> $LOG
echo "Instalacao deste sistema foi realizada em" >> $LOG

date >> $LOG 