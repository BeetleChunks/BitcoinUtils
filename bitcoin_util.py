import hashlib
import binascii
import struct
import base58
import sys

from ecdsa import SigningKey,SECP256k1
from ecdsa.util import PRNG
from optparse import OptionParser

class Bitcoin:
	def __init__(self, curve=SECP256k1, seed=None, version=None):
		self.EC_CURVE   = curve

		if seed == None:
			self.EC_SEED = 'DEADBEEF'
		else:
			self.EC_SEED = seed

		if version == None:
			self.BT_VERSION = 0x00
		else:
			self.BT_VERSION = version

		self.BT_ADDRESS = self.init_get_bitcoin_address()

	def init_get_bitcoin_address(self):
		privateKey   = self.get_private_ECDSA_key()
		publicKey    = self.get_public_ECDSA_key(privateKey)
		pubSHA256    = self.get_sha256_hash(publicKey)
		pubRIPEMD160 = self.get_ripemd160_hash(pubSHA256)
		pubVersioned = self.get_versioned_key(pubRIPEMD160)
		pub160SHA256 = self.get_sha256_hash(pubVersioned)
		pubSHA256x2  = self.get_sha256_hash(pub160SHA256)
		pubChecksum  = self.get_checksum_appended_hash(pubVersioned, pubSHA256x2)
		
		return self.get_base58check_string(pubChecksum)
	
	# 0 - Generate and return raw private ECDSA key
	def get_private_ECDSA_key(self):
		return SigningKey.generate(curve=self.EC_CURVE, entropy=PRNG(self.EC_SEED)).to_string()

	# 1 - Generate and return raw public ECDSA bitcoin standard key
	def get_public_ECDSA_key(self, privateKey):
		privateKey = SigningKey.from_string(privateKey, curve=self.EC_CURVE)
		privateKey = privateKey.get_verifying_key().to_string()

		privateKey = struct.pack('1B',*([4])) + privateKey

		return privateKey

	# 2 - Return SHA256 hash of public key
	# 5 - Return SHA256 hash of RIPEMD-160 hash
	# 6 - Return SHA256 hash of SHA256 hash
	def get_sha256_hash(self, publicKey):
		return hashlib.sha256(publicKey).digest()

	# 3 - Return RIPEMD-160 hash of public SHA256 key
	def get_ripemd160_hash(self, pubSHA256):
		h = hashlib.new('ripemd160')
		h.update(pubSHA256)

		return h.digest()

	# 4 - Return RIPEMD-160 hash with version added - 0x00 main network
	def get_versioned_key(self, pubRIPEMD160):
		return struct.pack('1B',*([self.BT_VERSION])) + pubRIPEMD160

	# 7 and 8 - Return the Stage 4 RIPEMD-160 hash with 4-byte checksum appended
	def get_checksum_appended_hash(self, pubVersioned, pubSHA256x2):
		checksum = []
		for i in range(0, 4):
			checksum.append(int(binascii.hexlify(pubSHA256x2[i]), 16))

		return pubVersioned + struct.pack('4B',*(checksum))

	# 9 - Return base58 string using Base58Check encoding
	def get_base58check_string(self, pubChecksum):
		return base58.b58encode(pubChecksum)

	# Print hex value of a raw key
	def print_hex_key(self, rawKey):
		print binascii.hexlify(rawKey).upper()

def getCommandLineArgs(printHelp=False):
	parser = OptionParser(add_help_option=False)

	parser.add_option(
			"--seed",
			help="Specify the seed value for private key creation (Default: DEADBEEF)",
			default=None,
			action="store",
			dest="seed")

	parser.add_option(
			"--version",
			help="Specify the hex version value (Default: 0x00)",
			default=None,
			type=int,
			action="store",
			dest="version")

	parser.add_option(
			"-h", "--help",
			help="Display this help message",
			default=False,
			action="store_true",
			dest="printHelp")

	optsAndArgs = parser.parse_args()

	if (printHelp == True or optsAndArgs[0].printHelp == True):
		parser.print_help()

		print "\nExamples:\n"
		print "bitcoin_util.py --seed Sup3rS3cr3tP4ss"
		print "bitcoin_util.py --version 0x05 --seed Sup3rS3cr3tP4ss"
		print "\n"

		sys.exit(0)

	return optsAndArgs

def main():
	(options, args) = getCommandLineArgs()

	bc = Bitcoin(seed=options.seed, version=options.version)
	print bc.BT_ADDRESS

if __name__ == '__main__':
	main()
