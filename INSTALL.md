# Installation

## Scapy

This software is based on Scapy. First and foremost, you must 
install Scapy and its dependencies, preferably with Python 2.6.
Instructions on how to do this can be found online at
http://www.secdev.org/projects/scapy/doc/installation.html.

## sendrecv Patch

After Scapy is installed, locate the Scapy source directory within your Python installation, most likely under either dist-packages or site-packages. Once you have located the Scapy source directory you must replace the version of sendrecv.py within that directory with the one provided with PacketKnife.

Once Scapy is installed and `sendrecv.py` is replaced, you should be set to go. Fire up a terminal/cmd shell/console, navigate to the PacketKnife source directory, and run:

    $ python2.6 projectmain.py


## Root/Admin Privileges

You may find that you need root/administrative privileges in order to complete this process. Chances are, if you are using this tool, you already know all about this. However, if not, here are some heads ups.

In Windows, this is accomplished by running the shell as Administrator.

In Linux, try:

    $ sudo python2.6 projectmain.py


## In Conclusion

That should be about it. Go and do good.