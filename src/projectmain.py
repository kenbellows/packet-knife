#!/usr/bin/python2.6
import time
import inspect
import pprint
from scapy.all import *
from HTTP import *
import sniff_data
import sniff_thread
import traceback
import pickle

PROG_NAME = "PacketKnife"
VERSION_NUM = "0.1beta"

class Harness:
    hostdict = {}
    def __init__(self):
        self.cmds = {
            "sniff" : self.runfg,
            "sniffbg" : self.runbg,
            "stopbg" : self.stopbg,
            "show" : self.showdata,
            "help" : self.printhelp,
            "loadpcap" : self.loadpcap,
            "save" : self.pickle,
            "load" : self.unpickle,
            "about" : self.about,
            "hosts" : self.showhosts
        }
        self.bgthread = None
        self.mainLoop()
    
    def mainLoop(self):
        while True:
            try:
                cmd_str = raw_input('>>> ')
                if cmd_str.strip() == "":
                    continue
                elif cmd_str == "quit":
                     break
                else:
                    cmd_words = cmd_str.split()
                    cmd, args = cmd_words[0], cmd_words[1:]
                    self.handleCmd(cmd, args)
            except KeyboardInterrupt:
                print
                break
            except:
                print traceback.format_exc()
    
    def handleCmd(self, cmd, args):
        if cmd in self.cmds:
            #try:
            self.cmds[cmd](*args)
            #except TypeError, e:
            #    print e
            #    print "Sorry, I think you handed me the wrong number of arguments. This function needs %d arguments.\nType 'help <command>' if you would like assistance." % len(inspect.getargspec(self.cmds[cmd]).args)
        else:
            print "Sorry, friend, don't know that one."
    
    """
        The commands
    """
    def runfg(self):
        """
            Run the credential and cookie sniffing process in the foreground so you can watch as info is gathered.
            Syntax:
                        sniff
            (Takes no arguments)
        """
        print "Listening for credentials and cookies."
        print "Hit Ctrl+C to stop listening and return shell."
        print "-----------------------------------------------"
        try:
            sniff(lfilter=lambda x: HTTP in x, prn=lambda x: sniff_data.callback(x, self.hostdict), store=0)
        except KeyboardInterrupt:
            print
            print
            return
    
    def runbg(self):
        """
            Run the credential and cookie sniffing process in the background so you can attend to other important matters whilst the data rolls in.
            Syntax:
                        sniffbg
            (Takes no arguments)
        """
        self.bgthread = sniff_thread.SniffThread(lfilter=lambda x: HTTP in x, prn=lambda x: sniff_data.callback(x, self.hostdict))
        self.bgthread.start()
    
    def stopbg(self):
        """
            Take a break from the credential and cookie sniffing process in the background so you can review your data, get a coffee, see a movie...
            Syntax:
                        stopbg
            (Takes no arguments)
        """
        if self.bgthread:
            self.bgthread.stop()
        
    def showhosts(self):
        """
            List all hosts for which the system currently has captured data.
            Syntax:
                        hosts
            (Takes no arguments)
        """
        if len(self.hostdict) > 0:
            for host in self.hostdict:
                print host
        else:
            print "(No data currently in the system.)   <== That is a system message, not the name of a host. This is also not the name of a host."
        
    def showdata(self, host=None):
        """
            Retrieve some of that sweet, sweet data honey you've collected.
            Syntax:
                        show [hostname]
            Parameters:
                        hostname:   Optional. If hostname is provided, output will be limited to this host (if you've got data for it).
                                    If hostname is omitted, data about all hosts will be thrown wildly at the screen.
        """ 
        def showdata_helper(hostname):
            try:
                data = self.hostdict[hostname]
            except IndexError:
                print "Sorry, I don't have anything on that host. If you type 'show', you can see data for all the hosts I have in storage."
                return
            print
            print hostname
            print "-"*len(hostname)
            if len(data["credentials"]) > 0:
                print "Credentials:"
                for username in data["credentials"]:
                    if username is not None:
                        print "  Username: ", username
                        if len(data["credentials"][username])> 0:
                            print "  Possible password(s): ", data["credentials"][username]
                print
            if len(data["cookies"]) > 0:
                print "Cookies:"
                for category in data["cookies"]:
                    if data["cookies"][category] == None:
                        continue
                    print "    "+category+":"
                    if type(data["cookies"][category]) == list:
                        d = {}
                        for pair in data["cookies"][category]:
                            d[pair[0]] = pair[1]
                        data["cookies"][category] = d
                    for c in data["cookies"][category]:
                        print "      "+c+" : "+data["cookies"][category][c]
        # End Helper Function
        
        if host:
            if host in self.hostdict:
                showdata_helper(host)
            else:
                print "Sorry, I don't think we have anything for "+str(host)
        else:
            for host in self.hostdict:
                showdata_helper(host)

            
    def printhelp(self, cmd=None):
        """
            List the available commands or further describe a single command.
            Syntax:
                        help [command]
            Parameters:
                        command:    Optional. If command is provided, a more detailed description of this command's usage will be provided.
                                    If not, a list of available commands with a brief description of each will be provided instead.
        """
        if not cmd:
            print "Here's a list of the available commands:"
            for c in self.cmds:
                try:
                    padding = " "*(12-len(c))
                    description = (inspect.getdoc(self.cmds[c]) or "").split('\n')[0]
                    print "  " + c + padding + description
                except Exception, e:
                    print repr(e)
        else:
            if cmd in self.cmds:
                description = (inspect.getdoc(self.cmds[cmd]) or ("Takes " + str(len(inspect.getargspec(self.cmds[cmd]).args) or "no") + " arguments"))
                print cmd+":   "+description
            else:
                print "Couldn't find a command named " + cmd + "; if you type 'help' you'll get a list of the available commands."
    
    def loadpcap(self, pcapfile):
        """
            List the available commands or further describe a single command.
            Syntax:
                        loadpcap filename
            Parameters:
                        filename:   The path to and name of the pcap file to be loaded.
        """
        p = rdpcap(pcapfile)
        if p is None:
            print "Couldn't file that file, mate."
            return
        for pkt in p:
            if HTTP in pkt:
                sniff_data.callback(pkt, self.hostdict)
        print "File", pcapfile, "loaded and processed.\nIf nothing went wrong, you should be able to show your results now."
    
    def pickle(self, filename):
        """
            Save your current data to a file for later use.
            Syntax:
                        save filename
            Parameters:
                        filename:   The path to and name of the file where the data should be stored.
                                    WARNING: This will overwrite any existing file at that location.
        """
        with open(filename, 'wb') as picklefile:
            pickle.dump(self.hostdict, picklefile)
        
    def unpickle(self, filename):
        """
            Load previously saved data from a file.
            Syntax:
                        save filename
            Parameters:
                        filename:   The path to and name of the file to be loaded.
                                    WARNING: This will overwrite any existing data from this session.
        """
        with open(filename) as picklefile:
            self.hostdict = pickle.load(picklefile)
    
    def about(self):
        """Print a nice overview of the software you're currently using."""
        print PROG_NAME, "v"+VERSION_NUM
        print "Original Author: Ken Bellows"
        print "Written for Introduction to Ethical Hacking, Johns Hopkins University"
        print "Professors Tom Llanso and Michael Smeltzer"
        print
        print "The purpose of this software is to be used as an information gathering tool as part of a penetration test."
        print "As such, it is is entirely passive; it will never send any packets, ARP spoof a target for you, or perform any other sort of attack."
        print
        print "What it *will* do, however, is allow you to retrieve usernames, passwords, and session cookies, along with other cookies deemed potentially interesting,"
        print "organizing it by hostname and user. This puts a penetration tester a few steps ahead, provided they can situate themselves on a useful network and begin sniffing useful packets."
        
    
if __name__ == "__main__":
    print PROG_NAME, "v"+VERSION_NUM
    print "Original Author: Ken Bellows"
    print "Written for Introduction to Ethical Hacking, Johns Hopkins University"
    print "Professors Tom Llanso and Michael Smeltzer"
    print
    print "Type 'help' for a list of commands."
    print "Type 'quit' or press Ctrl+C to end the program."
    print 
    print "Please don't do anything evil with this."
    h = Harness()
