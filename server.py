import socket
import binascii
from zlib import crc32
import hashlib
import struct
import json
import argparse
import multiprocessing as mp
import time
import pdb

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
                streams[streamConfig['id']] = UDPStream(streamConfig['binary_path'], streamConfig['key_path'])

        print('Validator process is ready...')

        while True:
            udp = UDPStruct(queue.get())
            UDPHelper.validateSeq(udp, streams, errorQueue)
            UDPHelper.validateCkSum(udp, streams, errorQueue)

    def _logger(self, queue):
        print('Logger process is ready...')

        while True:
            time.sleep(10)

            with open('checksum_failures.log', 'a') as f:
                while not queue.empty():
                    f.write(queue.get())

class UDPStruct(object):

    def __init__(self, data):
        cksum = data[12:-64]

        self.id = str(int.from_bytes(data[:4], 'big'))
        self.seq = int.from_bytes(data[4:8], 'big')
        self.key = data[8:10]
        self.numcksum = int.from_bytes(data[10:12], 'big')
        self.cksums = [int.from_bytes(cksum[x:x + 4], 'big') for x in range(0, len(cksum), 4)]
        self.message = data[:-64]
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
            data = f.read()
            exp = int.from_bytes(data[:3], 'little')
            mod = int.from_bytes(data[3:], 'little')
            self.pubKey = (exp, mod)

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
            errorMsg = UDPHelper.sequenceErrorMsg(udp, streams[udp.id].seq)
            errorQueue.put(errorMsg)

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

    @staticmethod
    def sequenceErrorMsg(udp, expected):
        errorMsg = udp.id + ' ' + str(udp.seq) + ' ' + str(expected) + ' (expected sequence)\n'
        return errorMsg

    @staticmethod
    def bytes2int(bytestr):
        if len(bytestr) == 2:
            return struct.unpack('>H', bytestr)
        if len(bytestr) == 4:
            return struct.unpack('>L', bytestr)

    @staticmethod
    def verifyRSA(pubKey, signature, message):
        sha256ans1 = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
        e = pubKey[0]
        m = pubKey[1]

        cipherint = int.from_bytes(signature, 'big')
        clearint = pow(cipherint, e, m)
        clearsig = clearint.to_bytes(len(signature), byteorder='big')

        digest = hashlib.sha256(message).digest()
        cleartext = sha256ans1 + digest
        expected = UDPHelper._pad_for_signing(cleartext, 64)

    @staticmethod
    def _pad_for_signing(message, target_length):
        max_msglength = target_length - 11
        msglength = len(message)

        if msglength > max_msglength:
            raise OverflowError('%i bytes needed for message, but there is only'
                                ' space for %i' % (msglength, max_msglength))

        padding_length = target_length - msglength - 3

        return b''.join([b'\x00\x01',
                           padding_length * b'\xff',
                           b'\x00',
                           message])



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='UDP checksum verification server')
    parser.add_argument('-c', action='store', dest='config_path', required=True,
            help='Store config file path')
    result = parser.parse_args()

    server = UDPServer(result.config_path)
    server.run()
