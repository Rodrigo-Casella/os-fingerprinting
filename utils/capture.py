import pcap


class Capture:

    def __init__(self, input, *, filter=None, immediate_mode=False, timeout=0):
        self.handle = pcap.pcap(name=input, immediate=immediate_mode, timeout_ms=timeout)

        if filter:
            self.handle.setfilter(filter)


    def read(self):
        return iter(self.handle)