import socket
import binascii
from zlib import crc32
import struct
import json
import argparse
import multiprocessing as mp
import time

class UDPServer(object):

    def __init__(self, configPath):
        self.bufsz = 3600
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
        self.errorQueue = mp.Queue(maxsize=0)
        self.process = mp.Process(target=self._process, args=(configPath, self.queue, 
            self.errorQueue))
        self.logger = mp.Process(target=self._logger, args=(self.errorQueue,))

    def run(self):
        self.process.start()
        self.logger.start()

    def put(self, data):
        self.queue.put(data)

    def putError(self, error):
        self.errorQueue(error)

    def _process(self, configPath, queue, errorQueue):
        streams = {}

        with open(configPath, 'r') as f:
            config = json.load(f)
            for streamConfig in config:
                streams[streamConfig['id']] = UDPStream(streamConfig['binary_path'])

        print('Validator process is ready...')

        while True:
            udp = UDPStruct(queue.get())
            UDPHelper.validateSeq(udp, streams, errorQueue)
            UDPHelper.validateCkSum(udp, streams, errorQueue)

    def _logger(self, queue):
        print('Logger process is ready...')

        while True:
            time.sleep(10)
            while not queue.empty():
                print(queue.get())

            #with open('checksum_failures.log', 'a') as f:
                #while not errors.empty():
                    #f.write(errors.pop(0))

class UDPStruct(object):

    def __init__(self, data):
        cksum = data[12:-64]

        self.id = str(int.from_bytes(data[:4], 'big'))
        self.seq = int.from_bytes(data[4:8], 'big')
        self.key = data[8:10]
        self.numcksum = int.from_bytes(data[10:12], 'big')
        self.cksums = [int.from_bytes(cksum[x:x + 4], 'big') for x in range(0, len(cksum), 4)]

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
    def validateCkSum(udp, streams, errorQueue):
        stream = streams[udp.id]
        xorKey = int.from_bytes(udp.key * 2, 'big')

        for cksum in udp.cksums:
            crc32 = UDPHelper.getCRC32(stream.data, stream.cycle)
            stream.seq += 1
            stream.cycle = crc32
            actual = crc32 ^ xorKey

            if actual != cksum:
                errorMsg = UDPHelper.checksumErrorMsg(udp, hex(cksum), hex(actual))
                errorQueue.put(errorMsg)


    @staticmethod
    def validateSeq(udp, streams, errorQueue):
        if streams[udp.id].seq != udp.seq:
            errorQueue.put('Sequence out of order')

    @staticmethod
    def getCRC32(data, cyclic=None):
        if cyclic:
            return crc32(data, cyclic) & 0xffffffff
        else:
            return crc32(data) & 0xffffffff

    @staticmethod
    def checksumErrorMsg(udp, received, expected):
        errorMsg = udp.id + ' ' + str(udp.seq) + ' ' + received + ' (received hash) ' + expected + ' (expected hash) ' + '\n'
        return errorMsg

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='UDP checksum verification server')
    parser.add_argument('-c', action='store', dest='config_path', required=True,
            help='Store config file path')
    result = parser.parse_args()

    server = UDPServer(result.config_path)
    server.run()
