import signal
import subprocess
import tempfile
import threading
import time
from scapy.all import *

class Sniffer():
    popenlock = threading.Lock()

    def __init__(self, iface, my_filter=None):
        self.iface = iface
        self.filter = my_filter
        self.proc = None
        tmpnam = "pcap_" + iface + "_"
        self.fnamefd, self.fname = tempfile.mkstemp(prefix=tmpnam)
        return

    def capture(self):
        """Starts the sniffer as a separate process"""
        if self.proc:
            self.proc.kill()
        self.proc = None

        args = []
        args += ["/usr/sbin/tcpdump", "-l", "-nN",
                 "-i", self.iface,
                 "-w", self.fname,
                 "-s", str(3000),
                 "-U"]

        if self.filter:
            if not isinstance(self.filter, list):
                self.filter = [self.filter]
            args += self.filter

        # Lock thread, popen might not be thread safe
        Sniffer.popenlock.acquire()
        try:
            print('Starting tcpdump cmd: %s' % ' '.join(args))
            self.proc = subprocess.Popen(args=args, stderr=subprocess.PIPE)
        finally:
            Sniffer.popenlock.release()

        self.proc.stderr.readline()

        return

    def kill_and_wait(self):
        """Stop the running process if any and wait for it to finish"""
        if not self.proc:
            return False

        self.proc.send_signal(signal.SIGINT)
        time.sleep(0.5)
        if not self.proc.poll():
            # Process is still alive
            time.sleep(1)
            try:
                self.proc.kill()
            except OSError:
                pass

        self.proc.wait()
        self.proc = None

        return True

    def report(self):
        """Terminate the sniffer and return the gathered data"""
        if not self.kill_and_wait():
            return None

        if not os.path.exists(self.fname):
            return []
        if os.path.getsize(self.fname) == 0:
            return []
        try:
            cap = rdpcap(self.fname)
        except Scapy_Exception:  # No packets received
            return []

        os.remove(self.fname)

        return cap
