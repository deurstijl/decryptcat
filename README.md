Decryptcat
===============

Due to an implementation "feature" in cryptcat it's trivial to brute-force the encryption key for a cryptcat encrypted network stream.
Based on the original cryptcat sourcecode: [http://cryptcat.sourceforge.net/](http://cryptcat.sourceforge.net/).

## Decrypt "feature"
When encrypting network traffic using cryptcat the first block contains the size of the actual payload block, and a random number: 

From function farm9crypt_write:
```c
 sprintf( tempbuf, "%d %d", size, rand() );
```
This means that when decrypting, the first 8 bytes should contain digits and a space if the decryption key is correct. 

## Installation
Just type make with the architecture: `make linux`

## Usage
* Capture or extract the encrypted stream using wireshark/tcpdump and save to a file "encrypted_file"
* Start brute-forcing by specifying a wordlist: `./decryptcat encrypted_file wordlist` 
* wait and profit.
* Note: When decrypting fails using the cryptcat from sourceforge, try the one from your linux repository

A sample encrypted file is included for you to test
