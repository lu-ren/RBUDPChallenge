import socket
import binascii
from zlib import crc32
import struct
import json
import argparse
import pdb

class UDPServer(object):

    def __init__(self, configPath):
        self.bufsz = 1400
        self.ip = '127.0.0.1'
        self.port = 1337
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.ip, self.port))
        #Stores binary data in dictionary...although takes up space in memory
        #it allows for faster computation of the checksum
        self.streams = {}

        with open(configPath, 'r') as f:
            config = json.load(f)
            for streamConfig in config:
                self.streams[streamConfig['id']] = UDPStream(streamConfig['binary_path'])

    def run(self):
        print "Serving is listening to port %d" % self.port

        while True:
            data = self.socket.recv(self.bufsz)
            #pdb.set_trace()
            udp = UDPStruct(data)
            self.validateCkSum(udp)
            self.validateSeq(udp)

    def validateCkSum(self, udp):
        stream = self.streams[udp.id]
        xorKey = ByteHelper.bytesToUInt(udp.key + udp.key)

        for cksum in udp.cksums:
            actual = ByteHelper.getCRC32(stream.data, stream.cycle)
            if actual ^ xorKey != cksum:
                print('Invalid cksum') #process error here
            else:
                stream.cycle = actual
                stream.seq += 1

    def validateSeq(self, udp):
        if self.streams[udp.id].seq != udp.seq: #process error here
            print('Sequence out of order')

class UDPStruct(object):

    def __init__(self, data):
        cksum = data[12:-64]

        self.id = str(ByteHelper.bytesToUInt(data[:4]))
        self.seq = ByteHelper.bytesToUInt(data[4:8])
        self.key = data[8:10]
        self.numcksum = ByteHelper.bytesToUInt(data[10:12])
        self.cksums = [ByteHelper.bytesToUInt(cksum[x:x + 4]) for x in xrange(0, len(cksum), 4)]
        self.sig = data[-64:]

    def __repr__(self):
        return '<id: %s, seq: %d, key: %s, numcksum: %d>' % (self.id, 
                self.seq, binascii.hexlify(self.key), self.numcksum)

class UDPStream(object):

    def __init__(self, binary_path):
        self.seq = 0
        self.cycle = None

        with open(binary_path) as f:
            self.data = f.read()

class ByteHelper(object):

    @staticmethod
    def bytesToUInt(byteStr):
        if len(byteStr) == 2:
            return struct.unpack('>H', byteStr)[0]
        if len(byteStr) == 4:
            return struct.unpack('>L', byteStr)[0]
        raise ValueError('Hex string must have length of 2 or 4')

    @staticmethod
    def getCRC32(data, cyclic=None):
        if cyclic:
            return crc32(data, cyclic) & 0xffffffff
        else:
            return crc32(data) & 0xffffffff

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='UDP checksum verification server')
    parser.add_argument('-c', action='store', dest='config_path', required=True,
            help='Store config file path')
    result = parser.parse_args()

    server = UDPServer(result.config_path)
    server.run()
