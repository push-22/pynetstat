# pynetstat
wrapper around the windows netstat command

*************** WINDOWS ONLY ***************

a python wrapper around the output of netstat

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

This should display the addresses/ports in use by the adb.exe process (if adb is running)

pynetstat estab

will show all the addresses/ports that have established connections

