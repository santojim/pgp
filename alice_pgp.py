#!/usr/bin/python3
#ALICE
import pgpy
import collections
from pathlib import Path
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm, EllipticCurveOID

#before key genereation, check if we already have created a key
#if exists, load it
alice_key_exists=Path("alice_key.asc")
if alice_key_exists.is_file():
    key, _ = pgpy.PGPKey.from_file('alice_key.asc')
#    print ('imported Alice private key = \n', key)
#    print ('imported Alice public key = \n', key.pubkey)
else:
    # we can start by generating a primary key. For this example, we'll use ECDSA and NIST_P384 curve
    key = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P384)

    # we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
    uid = pgpy.PGPUID.new('Alice', email='alice@alice.com')

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
    # any preference(s) needed for actions by this subkey that not specified here
    # will seamlessly "inherit" from those specified on the selected User ID
    key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})
    #print(subkey.pubkey)
    #print(subkey)
    subkey.pubkey |= key.certify(subkey.pubkey)

    # save this key as Alice's
    keybytes = bytes(key)
    with open("alice_key"+ ".asc", 'wb') as fo:
       fo.write(keybytes)

# get key id for subkey which uses ECDH encryption
# print(key.subkeys)
for keyid, value in key.subkeys.items():
    print ("key: ",keyid)
# subkey.pubkey
# print(key.subkeys[keyid].pubkey)
# subkey private key
# print(key.subkeys[keyid])

# export Alice's public subkey (ECDH) in a file so, Bob can retrieve it
# and encrypt his message using Alice's pub key

#print(key.subkeys[keyid].pubkey)
#pub_keybytes = bytes(key.subkeys[keyid].pubkey)
keybytes = bytes(key.pubkey)
with open("alice_pubkey"+ ".asc", 'wb') as fo:
   fo.write(keybytes)

#import Bob's public key in keyring
bob_key_exists = Path("bob_pubkey.asc")
if bob_key_exists.is_file():
    bobpubkey, _ = pgpy.PGPKey.from_file('bob_pubkey.asc')
    # print ('imported Bob public key = \n', bobpubkey)
    # open message from Bob
    message_exists = Path("message_for_alice")
    if message_exists.is_file():
        # import message from file
        message_from_bob = pgpy.PGPMessage.from_file("message_for_alice")
        #print(message_from_bob)

        #Now decrypt message from Bob using Alice's private subkey (ECDH)
        dec_msg = key.subkeys[keyid].decrypt(message_from_bob)
        # print ('decrypted message :\n', dec_msg)

        # verify signature on success it prints <SignatureVerification(True)>
        print(bobpubkey.verify(dec_msg))

        print (' message :\n', dec_msg.message)
    else:
        print("No message to decrypt")
else:
    print ('Bob\'s public key not found\n')
