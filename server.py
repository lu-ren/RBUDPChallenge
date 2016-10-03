import socket
import pdb

class UDPServer(object):

    def __init__(self, port):
        self.bufsz = 1400
        self.ip = '127.0.0.1'
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.ip, self.port))
        self.streams = {}

    def run(self):
        print "Serving is listening to port %d" % self.port

        while True:
            data = bytearray(self.socket.recv(self.bufsz))
            pdb.set_trace()
            udp = UDPStruct(data)
            print(udp)


class UDPStruct(object):

    def __init__(self, udpBytes):
        self.bytes = udpBytes
        self.id = self.bytes[:4]
        self.seq = self.bytes[4:8]
        self.key = self.bytes[8:10]
        self.numcksum = self.bytes[10:12]
        self.cksum = zip(*(iter(self.bytes[12:-64]),) * 4)
        self.sig = self.bytes[-64:]

    def __repr__(self):
        return '<id: %s, seq: %d, key: %s, numcksum: %d>' % (UDPStruct.formatByteArray(self.id), 
                UDPStruct.bytesToUInt(self.seq), UDPStruct.formatByteArray(self.key), 
                UDPStruct.bytesToUInt(self.numcksum))

    @staticmethod
    def formatByteArray(byteArray):
        return ''.join('{:02x}'.format(x) for x in byteArray)

    @staticmethod
    def bytesToUInt(byteArray):
        assert(len(byteArray) <= 4)
        numBytes = len(byteArray)
        ret = 0
        count = 0
        for byte in byteArray:
            ret |= byte << (8 * (numBytes - count - 1))
            count += 1

        return ret

class UDPStream(object):

    def __init__():
        self.seq = 0
        self.prevCksum = None

if __name__ == '__main__':
    server = UDPServer(1337)
    server.run()
