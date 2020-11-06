## RSA operations

### Description
This software impelements the following operations using RSA cryptography built from scratch in C:
* Key generation (KDF)
* RSA encryption 
* RSA decryption

### !Disclaimer 
This software is for auditing purposes only as it has not 
been tested on many different scenarios and security vulnerabilities. 
Cryptographic software demands high levels of expertise and 
security optimization for production. 

### Implementation 
###### Key generation
The key generation is implemented as a key deriviation function following the classic RSA modular arithmetic to produce numbers such that:
* Given the numbers, it is computationally fast to produce the output
* Without the numbers, it is computationally infeasible to guess the output\

In asymmetric cryptography such as RSA, the key generation creates two keys, a private key that is known only to the owner and a public key which is published to allow others to send encrypted messages to the owner.

###### Encryption - Decryption 
In Public Key Cryptography the encryption/decryption proccess is implemented by using modular exponentiation using the other party's public key such that only a party with the corresponding private key could decrypt the message.  Specifically,
* If Alice encrypts a message using Bob's public key, then only Bob's private key would be able to decrypt the message.
* If Alice encrypts a message using her private key, then anyone in knowledge of Alice's public key could decrypt the message. That would mean that the message is not actually encrypted, but in essence it is signed by Alice and anyone else can verify it.

###### Math specifics
For RSA, the keys are created by a series of computations based on number theory. At the end, the private key consists of numbers n, d while the public key consists of numbers n, e. The principle behind RSA is that for these numbers the equivalence $$(m^d)^e\equiv m\mod n$$ is true.

* Encrypting the message produces: 
$$m^e\equiv c\mod n$$
* Decrypting the message produces:
$$c^d=(m^d)^e\equiv m\mod n$$

#### Results
The software creates all the files successfully.


