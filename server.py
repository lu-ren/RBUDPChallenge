import socket
import binascii
from zlib import crc32
import struct
import json
import argparse
import multiprocessing as mp
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
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
                streams[streamConfig['id']] = UDPStream(streamConfig['binary_path'],
                                                streamConfig['key_path'])

        print('Validator process is ready...')
        while True:
            udp = UDPStruct(queue.get())
            print(udp.seq, ' ', udp.numcksum)
            UDPHelper.validateSeq(udp, streams)
            UDPHelper.validateCkSum(udp, streams)
            UDPHelper.validateSig(udp, streams)


class UDPStruct(object):

    def __init__(self, data):
        cksum = data[12:-64]

        self.id = str(int.from_bytes(data[:4], 'big'))
        self.seq = int.from_bytes(data[4:8], 'big')
        self.key = data[8:10]
        self.numcksum = int.from_bytes(data[10:12], 'big')
        self.cksums = [int.from_bytes(cksum[x:x + 4], 'big') for x in range(0, len(cksum), 4)]
        self.hash = SHA256.new(data[:-64]).digest()
        self.sig = data[-64:]

    def __repr__(self):
        return '<id: %s, seq: %d, key: %s, numcksum: %d>' % (self.id, 
                self.seq, binascii.hexlify(self.key), self.numcksum)

class UDPStream(object):

    def __init__(self, binary_path, key_path):
        self.seq = 0
        self.cycle = None

        with open(binary_path, 'rb') as f:
            self.data = f.read()

        with open(key_path, 'rb') as f:
            key_data = f.read()
            pKey_data = int.from_bytes(key_data[:-3], 'little')
            exp_data = int.from_bytes(key_data[-3:], 'little')
            self.pKey = RSA.construct((pKey_data, exp_data))

class UDPHelper(object):

    @staticmethod
    def validateCkSum(udp, streams):
        stream = streams[udp.id]
        xorKey = int.from_bytes(udp.key + udp.key, 'big')

        for cksum in udp.cksums:
            actual = UDPHelper.getCRC32(stream.data, stream.cycle)
            stream.seq += 1
            stream.cycle = actual

            if actual ^ xorKey != cksum:
                print('Invalid cksum') #process error here

    @staticmethod
    def validateSig(udp, streams):
        stream = streams[udp.id]

        if not stream.pKey.verify(udp.hash, udp.sig):
            print('Verification failed')

    @staticmethod
    def validateSeq(udp, streams):
        if streams[udp.id].seq != udp.seq:
            print('Sequence out of order')
            return False
        return True

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
