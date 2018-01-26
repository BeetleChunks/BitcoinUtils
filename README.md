# BitcoinUtils
Simple set of functions to test bitcoin address generation
## Usage
  #### `$ bitcoint_util.py [options]`
  
## Options
  #### `--seed`
   ##### Specify the seed value for private key creation (Default: DEADBEEF)
  #### `--version`
   ##### Specify the hex version value (Default: 0x00)
  #### `--address`
   ##### Specify a bitcoin address and get date first seen and balance information
  #### `--privatekey`
   ##### Specify the private key in hex format
  #### `--wif`
   ##### Use if the supplied private key is in Wallit Import Format (WIF)
  #### `--testnet`
   ##### Use to generate a testnet key instead of mainnet
  #### `--checkbalance`
   ##### Use to check bitcoin address balance against http://blockchain.info
  #### `--validate`
   ##### Used to validate the supplied or generated WIF key's checksum
  #### `--help`
   ##### Display the usage and examples
  
## Examples
  #### `bitcoin_util.py --seed Sup3rS3cr3tP4ss`
  #### `bitcoin_util.py --version 0x05 --seed Sup3rS3cr3tP4ss`
  #### `bitcoin_util.py --seed Sup3rS3cr3tP4ss --testnet`
  #### `bitcoin_util.py --privatekey 4324D402...2B789323`
  #### `bitcoin_util.py --privatekey 5JKrgU8m...6ksEfPdP --wif`
  #### `bitcoin_util.py --privatekey 5JKrgU8m...6ksEfPdP --wif --validate`
  #### `bitcoin_util.py --privatekey 4324D402...2B789323 --validate --checkbalance`
