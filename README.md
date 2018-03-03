# WIFUnscrambler

## Purpose

If yo have got multiple parts of a WIF key and do not know their correct order, this script will go through all the possible combinations, and check which one leads to the given address (you need to know the address).

## Requirements

* itertools, base58, binascii, ecdsa, hashlib

## Usage

Configure Wif.py variables:

* `target_address`: String containing the target address. This has to be known; keep in mind that a scrambled WIF can generate millions of valid addresses.
* `head`: Array of the first parts of the WIF, ordered, if you are sure of them. Starts either with Q (compressed) or 6 (uncompressed). If you are unsure, set to `[""]` and add them to middle.
* `tail`: The last parts of the WIF, ordered if you are sure of them. If you are unsure, set to `[""]` and add them to middle.
* `verbosity`: Integer. The script will show status each number of checked private keys. Set verbosity to define that interval. If your CPU is fast, you may want to set that to something higher, in a way that you get less messages in a period of time.

The script will generate a file with named `{head}-log.txt`, for you to keep track of the process.

## Performances

Providing a head (1), a tail (1) and the knowledge that the address is compressed, the process runs through `11! = 39,916,800` combinations. This took around 7 h on an i3 6100 CPU. Should take 84 hours to run knowing only the head (`QCD6`) but not the tail. `12!` combinations would be processed.

Providing a head (1), a tail (1) and the knowledge that the address is compressed, the process would run through `11!` addresses but the time needed will be greater; in the average of 70 hours.

## Licence

No licence. Use it as you want.