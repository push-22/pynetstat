# pynetstat
wrapper around the windows netstat command

*************** WINDOWS ONLY ***************

a python wrapper around the output of netstat, it will apply a user supplied regex expression to the ouput of netstat
no checking of the expression is done (garbage in garbage out).

Installation
============
copy pynetstat.py and requirements.txt to some local folder
optionally put the folder on the systems path
fom a command line install the requirements.txt
pip install -r requirements.txt

usage
=====

from a command prompt type something like:

pynetstat

will return basic usage info

pynetstat -exe:adb.exe

This will display the addresses/ports in use by the adb.exe process, if adb is running, else nothing

pynetstat estab

will show all the addresses/ports that have established connections

pynetstat list -exe:adb

will display any address/port that is in the listening state for the adb.exe process
