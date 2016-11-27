# MyUDAP

net-udap based software to setup a squeezebox receiver

This software is based on [net-udap code of Robin Bowes](http://github.com/robinbowes/net-udap)  

This not complete, only read operations are supported right now..

The project is coded in Delphi.
No extra libs are needed except standard Delphi libraries.
It is a basic console application, build for Windows (Winsock2).

Code is reverse engineered from the Perl code of Robin Bowes project.
His code only worked for me in a Linux virtual machine because of the problems with the IO::Interface::Simple module.

So I decided to create my own version, for now in Delphi..

Discover is working, also get_ip and get_data.
Next up are set_ip and set_data.
... 