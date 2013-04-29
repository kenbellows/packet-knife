# PacketKnife v0.1beta

Author: Ken Bellows  
Written for Introduction to Ethical Hacking, Johns Hopkins University  
Professors Tom Llanso and Michael Smeltzer  

## License

This software is released under the GNU General Public License version 3.
You should have received a copy of the license with this software. If not,
it can be found online at https://gnu.org/licenses/gpl.html.


## About

PacketKnife is an interactive packet listening and extraction tool.

The purpose of this software is to be used as an information gathering tool as part of a penetration test.
As such, it is is entirely passive; it will never send any packets, ARP spoof a target for you, or perform any other sort of attack.

What it *will* do, however, is allow you to retrieve usernames, passwords, and session cookies, along with other cookies deemed potentially interesting, organizing it by hostname and user. This puts a penetration tester a few steps ahead, provided they can situate themselves on a useful network and begin sniffing useful packets.

Please don't do anything evil with this software.


## Usage

Commands available:

* about: Print a nice overview of the software you're currently using.  

* quit: Quit the program.  

* sniff: Run the credential and cookie sniffing process in the foreground so you can watch as info is gathered.  

* sniffbg: Run the credential and cookie sniffing process in the background so you can attend to other important matters whilst the data rolls in.  

* stopbg: Take a break from the credential and cookie sniffing process in the background so you can review your data, get a coffee, see a movie...  

* hosts: List all hosts for which the system currently has captured data.  

* show: Retrieve some of that sweet, sweet data honey you've collected.  
Syntax:  
    show [hostname]  
Parameters:  
    hostname: Optional. If hostname is provided, output will be limited to this host (if you've got data for it).  
              If hostname is omitted, data about all hosts will be thrown wildly at the screen.  

* help: List the available commands or further describe a single command.  
Syntax:  
    help [command]  
Parameters:  
    command: Optional. If command is provided, a more detailed description of this command's usage will be provided.  
             If not, a list of available commands with a brief description of each will be provided instead.  

* save: Save your current data to a file for later use.
Syntax:
    save filename
Parameters:
    filename:   The path to and name of the file where the data should be stored.
WARNING: This will overwrite any existing file at that location.

* load: Load previously saved data from a file.  
Syntax:  
    save filename  
Parameters:  
    filename:   The path to and name of the file to be loaded.  
WARNING: This will overwrite any existing data from this session.  

* loadpcap:    Load a pcap file into the self.hostdict dictionary  
Syntax:  
    loadpcap filename  
Parameters:  
    filename:   The path to and name of the pcap file to be loaded.  

