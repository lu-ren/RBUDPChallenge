import socket
import binascii
from zlib import crc32
import struct
import json
import argparse
import multiprocessing as mp
import pdb

class UDPServer(object):

    def __init__(self, configPath):
        self.bufsz = 1400
        self.ip = '127.0.0.1'
        self.port = 1337
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.ip, self.port))
        self.validator = Validator(configPath)

    def run(self):
        print("Serving is listening to port %d" % self.port)

        self.validator.run()

        while True:
            self.validator.put(self.socket.recv(self.bufsz))

class Validator(object):

    def __init__(self, configPath):
        self.queue = mp.Queue(maxsize=0)
        self.process = mp.Process(target=self._process, args=(configPath, self.queue))

    def run(self):
        self.process.start()

    def put(self, data):
        self.queue.put(data)

    def _process(self, configPath, queue):
        streams = {}

        with open(configPath, 'r') as f:
            config = json.load(f)
            for streamConfig in config:
                streams[streamConfig['id']] = UDPStream(streamConfig['binary_path'])

        print('Validator process is ready...')
        while True:
            udp = UDPStruct(queue.get())
            print(udp.seq, ' ', udp.numcksum)
            UDPHelper.validateSeq(udp, streams)
            UDPHelper.validateCkSum(udp, streams)


class UDPStruct(object):

    def __init__(self, data):
        cksum = data[12:-64]

        self.id = str(ByteHelper.bytesToUInt(data[:4]))
        self.seq = ByteHelper.bytesToUInt(data[4:8])
        self.key = data[8:10]
        self.numcksum = ByteHelper.bytesToUInt(data[10:12])
        self.cksums = [ByteHelper.bytesToUInt(cksum[x:x + 4]) for x in range(0, len(cksum), 4)]
        self.sig = data[-64:]

    def __repr__(self):
        return '<id: %s, seq: %d, key: %s, numcksum: %d>' % (self.id, 
                self.seq, binascii.hexlify(self.key), self.numcksum)

class UDPStream(object):

    def __init__(self, binary_path):
        self.seq = 0
        self.cycle = None

        with open(binary_path, 'rb') as f:
            self.data = f.read()

class UDPHelper(object):

    @staticmethod
    def validateCkSum(udp, streams):
        stream = streams[udp.id]
        xorKey = ByteHelper.bytesToUInt(udp.key + udp.key)

        for cksum in udp.cksums:
            actual = ByteHelper.getCRC32(stream.data, stream.cycle)
            stream.seq += 1
            stream.cycle = actual
            if actual ^ xorKey != cksum:
                print('Invalid cksum') #process error here

    @staticmethod
    def validateSeq(udp, streams):
        if streams[udp.id].seq != udp.seq:
            print('Sequence out of order')
            return False
        return True

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
