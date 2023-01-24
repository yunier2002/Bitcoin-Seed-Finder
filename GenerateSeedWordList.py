import csv
import time
import itertools
from binascii import hexlify
from typing import List
import unicodedata
import sqlite3

from embit import bip32, bip39, ec, base58, script, hashes
from embit.networks import NETWORKS
from embit.descriptor import Descriptor

start_time = time.time()

# Bitcoin 2048 word list
word_list = bip39.WORDLIST
net = NETWORKS['main']


known_word_list = ["blast", "trend", "solve", "giant", "soda", "lounge", "spell", "balcony", "knife", "sad"]  #Custom wordlist
address_to_find = "bc1q7kw2uepv6hfffhhxx2vplkkpcwsslcw9hsupc6"
Num_of_known_words = 10
Num_of_missing_words = 1  #Don't count last word as that is the checksum and will be calculated automatically later

# Starting words
#starting_words = ["word", "word", "word", "word", "word", "word", "word", "word", "word", "word"]

def calculate_checksum(partial_mnemonic: list) -> List[str]:
    """ Provide 11- or 23-word mnemonic, returns complete mnemonic w/checksum as a list """
    if len(partial_mnemonic) not in [11, 23]:
        raise Exception("Pass in a 11-word or 23-word mnemonic")

    # Work on a copy of the input list
    mnemonic_copy = partial_mnemonic.copy()

    # 12-word seeds contribute 7 bits of entropy to the final word; 24-word seeds
    # contribute 3 bits. But we don't have any partial entropy bits to use to help us
    # create the final word. So just default to filling those missing values with zeroes
    # ("abandon" is word 0000, so effectively inserts zeroes).
    mnemonic_copy.append("abandon")

    # Convert the resulting mnemonic to bytes, but we `ignore_checksum` validation
    # because we have to assume it's incorrect since we just hard-coded it above; we'll
    # fix that next.
    mnemonic_bytes = bip39.mnemonic_to_bytes(unicodedata.normalize("NFKD", " ".join(mnemonic_copy)),
                                             ignore_checksum=True, wordlist=word_list)

    # This function will convert the bytes back into a mnemonic, but it will also
    # calculate the proper checksum bits while doing so. For a 12-word seed it will just
    # overwrite the last 4 bits from the above result with the checksum; for a 24-word
    # seed it'll overwrite the last 8 bits.
    return bip39.mnemonic_from_bytes(mnemonic_bytes).split()

#Get all possible combinations of already known words
for known_list_permutations in itertools.permutations(known_word_list, Num_of_known_words):
    #print(known_list_permutations)

    for unknown_list_permutations in itertools.permutations(word_list, Num_of_missing_words):
        #print(unknown_list_permutations)
        partial_seed = list(known_list_permutations + unknown_list_permutations)
        #print(partial_seed)

        # Set the mnemonic words
        #mnemonic_words = "word word word word word word word word word word word word"

        # Impartial (11 or 23) seed words to generate checksum automatically
        #partial_seed = ['word', 'word', 'word', 'word', 'word', 'word', 'word', 'word', 'word', 'word', 'word'] # For testing purposes

        seed_with_checksum = calculate_checksum(partial_seed)
        #seed_with_checksum = ['word', 'word', 'word', 'word', 'word', 'word', 'word', 'word', 'word', 'word', 'word', 'word'] # For testing purposes
        print("Full Mnemonic Seed with Checksum: " + ' '.join(seed_with_checksum))

        # Generate root privkey, password can be omitted if you don't want it
        #seed = bip39.mnemonic_to_seed(' '.join(seed_with_checksum), password="test")
        seed = bip39.mnemonic_to_seed(' '.join(seed_with_checksum))

        root = bip32.HDKey.from_seed(seed)
        # print(root)

        bip84_derivation = "m/84h/0h/0h"

        # Derive and convert to pubkey
        MasterPK = root.derive(bip84_derivation)
        print("BIP32 Master Private Key: " + str(MasterPK))

        MasterPubKey = MasterPK.to_public()
        print("BIP32 Master Public Key: " + str(MasterPubKey))

        WalletFingerprint = hexlify(root.my_fingerprint).decode()
        print("Fingerprint: " + str(WalletFingerprint))

        # Generate native segwit descriptors.
        # You can use {0,1} for combined receive and change descriptors
        # desc = Descriptor.from_string(
        #     "wpkh([%s/84h/0h/0h]%s/{0,1}/*)" % (hexlify(root.my_fingerprint).decode(), MasterPubKey))
        # print("Full Descriptor: " + str(desc))
        # >>> wpkh([67c32a74/84h/0h/0h]xpub6CH26VtYLqm5nw8UKA2qH8doMrvGZUpeQst1JkrmyGo9LYRoKVnyfgdvjcVQoK4XSWUwyZEcupk8wBh6a2mLJ82ouUo9x2n1Y3zeoEcRSYr/{0,1}/*)

        # Print first X addresses
        for i in range(1):
            # print(desc.derive(i).key)
            # address = desc.derive(i).address()
            AddressPK = root.derive(bip84_derivation).derive([0, i]).key
            AddressPubKey = MasterPubKey.derive([0, i])

            address = script.p2wpkh(AddressPubKey).address()

            print("")
            print("Address PK: " + str(AddressPK))
            print("Address PubKey: " + str(AddressPubKey))
            print("Address: " + str(address))
            print("")

            # Code to query blockchain explorer locally to see if address has a balance
            # max_tries = 3  # the number of times you want to retry the request
            # for t in range(max_tries):
            #     try:
            #         url = "http://192.168.0.145:3006/api/address/" + address
            #         response = requests.get(url)
            #         UTXOsFound = response.json()
            #         UTXOsFound = UTXOsFound["chain_stats"]["funded_txo_count"]
            #         # If the request is successful, we exit the loop
            #         break
            #     except Exception as e:
            #         # If the request fails, we print the error message and retry
            #         print(f'Attempt {t + 1} failed: {e}')
            # else:
            #     # This code block will be executed if all retries fail
            #     print(f'All {max_tries} attempts failed')
            #     UTXOsFound = None


            if address == address_to_find:
                address_match = "Yes"
                print("UTXO FOUND!!!!!!!!!!!!")
                # write data to a CSV file
                with open('UsedAddressesFound.csv', 'a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([' '.join(seed_with_checksum), address, str(AddressPK)])
            else:
                address_match = "No"
                print("EMPTY ADDRESS")
                print("")

            # Save results of seeds processed to DB for later
            # Connect to the database
            conn = sqlite3.connect('SeedPermutations.db')
            cursor = conn.cursor()

            # Create a table to store the permutations
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS SeedsList (Seed TEXT, Address TEXT UNIQUE, PrvKey TEXT, UTXOs TEXT)
            ''')
            cursor.execute('INSERT OR IGNORE INTO SeedsList (Seed, Address, PrvKey, UTXOs) VALUES (?, ?, ?, ?)', (str(seed_with_checksum), str(address), str(AddressPK), address_match))

            # Commit the changes and close the connection
            conn.commit()
            conn.close()


end_time = time.time()

elapsed_time = (end_time - start_time) / 60
print("Time elapsed: ", elapsed_time)



