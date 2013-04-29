import threading
from scapy.all import sniff

class SniffThread(threading.Thread):
  """ A simple thread to manage Scapy sniffing in the background. """
  def __init__(self, lfilter, prn):
    threading.Thread.__init__(self)
    # Set self.stopsniffing boolean to False
    self.stopsniffing = False
    # If given an lfilter or a prn, store them for later use.
    self.lfilter = lfilter
    self.prn = prn
  def run(self):
    # Run a normal PacketKnife sniff, with the addition of the stopperTimeout being set to 0.1 second 
    # and the stopper function ebign set to a check of the value of self.stopsniffing
    sniff(store=0, lfilter=self.lfilter, prn=self.prn, stopperTimeout=0.1, stopper=lambda: self.stopsniffing)
  def stop(self):
    # Set self.stopsniffing to False. Now the next time the bg sniff checks the stopper function, it will stop.
    self.stopsniffing = True

if __name__ == "__main__":
  # Proof of concept; sniff for fifteen seconds.
  import time
  s = sniffthread()
  s.start()
  time.sleep(15)
  s.stop()
 
