#!/usr/bin/python3
#BOB
import pgpy
from pathlib import Path
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm, EllipticCurveOID

#before key genereation, check if we already have created a key
#if exists, load it
bob_key_exists=Path("bob_key.asc")
if bob_key_exists.is_file():
    key, _ = pgpy.PGPKey.from_file('bob_key.asc')
    #print ('imported Bob private key = \n', key)
    #print ('imported Bob public key = \n', key.pubkey)
else:
    # we can start by generating a primary key. For this example, we'll use ECDSA and NIST_P384 curve
    key = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P384)

    # we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
    uid = pgpy.PGPUID.new('Bob', email='bob@bob.gr')

    # now we must add the new user id to the key. We'll need to specify all of our preferences at this point
    # because PGPy doesn't have any built-in key preference defaults at this time
    # this example is similar to GnuPG 2.1.x defaults, with no expiration or preferred keyserver
    key.add_uid(uid, usage={KeyFlags.Sign},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

    # generate a subkey that uses Elliptic Curve Diffie Hellman for securing the communication channel
    subkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.NIST_P384)
    # preferences that are specific to the subkey can be chosen here
    # # any preference(s) needed for actions by this subkey that not specified here
    # # will seamlessly "inherit" from those specified on the selected User ID
    key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})

    # save this key as Bob's
    keybytes = bytes(key)
    with open("bob_key"+ ".asc", 'wb') as fo:
       fo.write(keybytes)
    # save this key as Bob's
    keybytes = bytes(subkey)
    with open("bob_subkey"+ ".asc", 'wb') as fo:
       fo.write(keybytes)

#export Bob's public key in a file so, Alice can retrieve it
pubkeybytes = bytes(key.pubkey)
with open("bob_pubkey"+ ".asc", 'wb') as fo:
   fo.write(pubkeybytes)

#import Alice's public key in keyring
alice_key_exists = Path("alice_pubkey.asc")
if alice_key_exists.is_file():
    alicekey, _ = pgpy.PGPKey.from_file('alice_pubkey.asc')
    #print ('imported Alice public key = \n', alicekey)
else:
    print ('Alice\'s public key not found\n')

# create a message
file_message = pgpy.PGPMessage.new("testfile", file=True)
#print ('file text message pgp form:\n', file_message)
#print ('file text message original form:\n', file_message.message)

# sign a message with Bob's private key
# the bitwise OR operator '|' is used to add a signature to a PGPMessage.
file_message |= key.sign(file_message)
#print ('signed file text message :\n', file_message)

# encrypt it using Alice's public key (if key exists)
if alice_key_exists.is_file():
    # encrypt the message using a symmetric cryptography algorithm
    # (AES256) with a pseudorandom key he generated
    cipher = pgpy.constants.SymmetricKeyAlgorithm.AES256
    sessionkey = cipher.gen_key()
    enc_msg = alicekey.encrypt(file_message, cipher=cipher, sessionkey=sessionkey)
    del sessionkey
    # write the encrypted message in a file so that Alice can open and decrypt it
    pgpbytes = bytes(enc_msg)
    with open("message_for_alice", 'wb') as fo:
       fo.write(pgpbytes)
#    print ('encrypted final message',enc_msg)
else:
    print ('Alice\' key doesn\'t exist yet')
