import requests
import hashlib
import binascii
import struct
import base58
import time
import sys
import timeit

from ecdsa import SigningKey,SECP256k1
from ecdsa.util import PRNG
from optparse import OptionParser

class Bitcoin:
	def __init__(self, curve=SECP256k1, seed=None, version=None, privateHexKey=None, 
		wif=False, testnet=False, address=None):
		
		if address == None:
			self.EC_CURVE   = curve
			self.TESTNET = testnet

			if seed == None:
				self.EC_SEED = 'DEADBEEF'
			else:
				self.EC_SEED = seed

			if version == None:
				self.BT_VERSION = 0x00
			else:
				self.BT_VERSION = version

			self.BT_ADDRESS = self.init_get_bitcoin_address(privateHexKey=privateHexKey, wif=wif)

		else:
			self.BT_ADDRESS = address

	def init_get_bitcoin_address(self, privateHexKey=None, wif=False):
		# This occurs if you do not specify a private key with the --privatekey flag
		# generating a private key with default "DEADBEEF" seed, unless --seed is specified
		if privateHexKey == None:
			self.BT_PRIV_KEY = self.get_private_ECDSA_key()

			self.BT_PRIV_WIF_KEY = self.get_wif_from_private_hex_key(binascii.hexlify(self.BT_PRIV_KEY))
			self.BT_PRIV_HEX_KEY = binascii.hexlify(self.BT_PRIV_KEY).upper()

		# This occurs if you specify a private hex key from the command line with the --privatekey
		# flag and also tac on the --wif flag, indicating the private key supplied is in WIF format
		elif wif == True:
			self.BT_PRIV_KEY = self.get_private_key_from_wif(privateHexKey)

			self.BT_PRIV_WIF_KEY = privateHexKey
			self.BT_PRIV_HEX_KEY = binascii.hexlify(self.BT_PRIV_KEY).upper()

		# This occurs if you specify a private hex key from the command line with the --privatekey
		# and do NOT supply the --wif flag, indicating the private key supplied is standard hex format
		else:
			self.BT_PRIV_KEY = binascii.unhexlify(privateHexKey)

			self.BT_PRIV_WIF_KEY = self.get_wif_from_private_hex_key(privateHexKey)
			self.BT_PRIV_HEX_KEY = binascii.hexlify(self.BT_PRIV_KEY).upper()

		publicKey        = self.get_public_ECDSA_key(self.BT_PRIV_KEY)
		pubSHA256        = self.get_sha256_hash(publicKey)
		pubRIPEMD160     = self.get_ripemd160_hash(pubSHA256)
		pubVersioned     = self.get_versioned_key(pubRIPEMD160)
		pub160SHA256     = self.get_sha256_hash(pubVersioned)
		pubSHA256x2      = self.get_sha256_hash(pub160SHA256)
		pubChecksum      = self.get_checksum_appended_hash(pubVersioned, pubSHA256x2)
		
		return self.get_base58check_string(pubChecksum)

	def get_wif_from_private_hex_key(self, privateHexKey):
		privateKey = binascii.unhexlify(privateHexKey)

		# 2 - add 0x80 byte in front for mainnet and 0xef for testnet
		if self.TESTNET == False:
			privateKey = struct.pack('1B',*([0x80])) + privateKey
		else:
			privateKey = struct.pack('1B',*([0xef])) + privateKey

		# 3 and 4 - perform SHA256 on the extended key and then again on result hash
		privSHA256 = self.get_sha256_hash(self.get_sha256_hash(privateKey))

		# 5 - use first 4 bytes of the result hash as the checksum
		privChecksum = privSHA256[0:4]

		# 6 - add 4 bytes from [5] to the end of the extended hash from [2]
		checksum = []
		for i in range(0, 4):
			checksum.append(int(binascii.hexlify(privChecksum[i]), 16))

		privCheckSumKey = privateKey + struct.pack('4B',*(checksum))

		# 7 - convert the resultant key to the base58check encoding
		wifPrivateB58Key = self.get_base58check_string(privCheckSumKey)

		return wifPrivateB58Key

	def get_private_key_from_wif(self, wifPrivateB58Key):
		privateHexKey = base58.b58decode(wifPrivateB58Key)
		return privateHexKey[1:-4]
	
	def get_wif_validated_checksum_status(self):
		privCheckSumKey = base58.b58decode(self.BT_PRIV_WIF_KEY)
		checksum        = privCheckSumKey[-4:]
		privateKey      = privCheckSumKey[0:-4]
		newChecksum     = self.get_sha256_hash(self.get_sha256_hash(privateKey))[0:4]

		if checksum == newChecksum:
			return True

		else:
			return False

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

	def check_address_first_seen(self):
		URI = 'http://blockchain.info/q/addressfirstseen/' + self.BT_ADDRESS
		response = requests.get(URI)
		
		return time.strftime("%a, %b %d, %Y %H:%M:%S %Z", time.localtime(int(response.text.encode('utf-8'), 0)))

	def check_address_balance(self):
		URI = 'http://blockchain.info/q/addressbalance/' + self.BT_ADDRESS
		response = requests.get(URI)
		
		return response.text.encode('utf-8')

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
			"--address",
			help="Specify a bitcoin address and get date first seen and balance information",
			default=None,
			action="store",
			dest="address")

	parser.add_option(
			"--privatekey",
			help="Specify the private key in hex format",
			default=None,
			action="store",
			dest="privatekey")

	parser.add_option(
			"--wif",
			help="Use if the supplied private key is in Wallit Import Format (WIF)",
			default=False,
			action="store_true",
			dest="wif")

	parser.add_option(
			"--testnet",
			help="Use to generate a testnet key instead of mainnet",
			default=False,
			action="store_true",
			dest="testnet")

	parser.add_option(
			"--checkbalance",
			help="Use to check bitcoin address balance against http://blockchain.info",
			default=False,
			action="store_true",
			dest="checkbalance")

	parser.add_option(
			"--validate",
			help="Used to validate the supplied or generated WIF key's checksum",
			default=False,
			action="store_true",
			dest="validate")

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
		print "  bitcoin_util.py --seed Sup3rS3cr3tP4ss"
		print "  bitcoin_util.py --version 0x05 --seed Sup3rS3cr3tP4ss"
		print "  bitcoin_util.py --seed Sup3rS3cr3tP4ss --testnet"
		print "  bitcoin_util.py --privatekey 4324D402...2B789323"
		print "  bitcoin_util.py --privatekey 5JKrgU8m...6ksEfPdP --wif"
		print "  bitcoin_util.py --privatekey 5JKrgU8m...6ksEfPdP --wif --validate"
		print "  bitcoin_util.py --privatekey 4324D402...2B789323 --validate --checkbalance"
		print "\n"

		sys.exit(0)

	return optsAndArgs

def main():
	(options, args) = getCommandLineArgs()

	bc = Bitcoin(seed=options.seed, version=options.version, privateHexKey=options.privatekey, 
			wif=options.wif, testnet=options.testnet, address=options.address)

	if options.address == None:
		print "\n"
		print "[+] BT Address      : " + bc.BT_ADDRESS
		print "[+] BT WIF PRIV KEY : " + bc.BT_PRIV_WIF_KEY
		print "[+] BT HEX PRIV KEY : " + bc.BT_PRIV_HEX_KEY

	else:
		print "\n"
		print "[+] BT Address      : " + bc.BT_ADDRESS

	if options.checkbalance == True or options.address != None:
		print "[+] First seen      : " + bc.check_address_first_seen()
		print "[+] Balance         : " + bc.check_address_balance()

	if options.validate == True and options.address == None:
		status = bc.get_wif_validated_checksum_status()

		if status == True:
			print "[+] Status          : Valid"

		else:
			print "[+] Status          : Invalid!"

	print "\n"

if __name__ == '__main__':
	main()
