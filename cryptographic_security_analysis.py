from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import hashlib
from hashlib import sha256
import os
import random

def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)
def bytes_to_hex(bytes_data):
    return bytes_data.hex()

def birthday_attack():
    collisions = {}
    while True:
        input_data = os.urandom(16)
        hash_value = myHash(input_data)

        if hash_value in collisions:
            return True
        collisions[hash_value] = input_data

        if len(collisions) > 100000:
            return False

def Encrypt(key: str, iv: str, data: str) -> str:
    # Purpose of the Encrypt function is to encrypt input data using AES-ECB mode,
    #  it starts with an initialisation vector (IV) and a key provided in the main test case, 
    #  the IV and Key are then converted into bytes using the helper function, and the input data is turned also into bytes.
    key_bytes = hex_to_bytes(key)
    iv_bytes = hex_to_bytes(iv)
    data_bytes = data.encode('utf-8')
    # Due to AES being 16 bytes cipher, this requires the splitting of input data's bytes into 16 byte blocks,
    #  especially if they exceed the length of the encryptor, which will then lead to splitting and the creation of the next block,
    #  the variable next_input is used both to initially carry the IV, and then later on carry the value of the previous ciphertext,
    #  as input to form the encryptor for the next block.
    #  blocks is a list that splits the input data into 16 byte blocks.  
    blocks = [data_bytes[i:i+16] for i in range(0, len(data_bytes), 16)]

    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    next_input = iv_bytes
    final_result = b''

    # A nested for loop is used, the out loop which ranges by block, and the inner loop which ranges,
    #  by the length of the block. Each iteration on the inner loop adds to the block_result variable,
    #  block_result will get reset after each inner loop iteration. block_result will hold the values of,
    #  XORing the current place value of encrypted with the current place value of block. 
    #  encrypted variable creates an encryption object from cipher for encryption. 
    #  initially in the very first iteration the IV is encrypted,  and used to then encrypt the first block, in the inner for loop
    #  after the encryption of the first block, inner loop is finished, next_input changes to the block_result's resulting value from,
    #  the inner loops full iteration. 
    #  Another variable final_result takes the total value of each block_result from each inner loop iteration.
    #  When outer loop finishes a rotation block_result is reset and next_input either holding the IV or the previous cipher is encrypted
    for block in blocks:
        encrypted = encryptor.update(next_input)
        block_result = b''
        for i in range(len(block)):
            block_result += bytes([encrypted[i] ^ block[i]])
        next_input = block_result
        final_result += block_result

    return bytes_to_hex(final_result)

def Decrypt(key: str, iv: str, data: str) -> str:
    key_bytes = hex_to_bytes(key)
    iv_bytes = hex_to_bytes(iv)
    data_bytes = hex_to_bytes(data)
    # Same logic as the encryption function. key and IV, and input data are used,
    # Turned to bytes, encrypto object is prepared which will initially encrypt the next_input(IV) 
    # and each previous block value onwards,
    # The same block splitting logic is applied here to ensure that if exceed 16 bytes, will split into blocks.
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB()) 
    encryptor = cipher.encryptor()
    
    next_input = iv_bytes
    final_result = b''
    blocks = [data_bytes[i:i+16] for i in range(0, len(data_bytes), 16)]

    # The solution with this decryption as shown in the diagram, XOR's the ciphertexts instead of the plaintext,
    # with the encryptor to logically result in revealing the plain text. 
    # The same nested blocks loop, with the inner block loop is used to ensure splitting.
    for block in blocks:
        encrypted = encryptor.update(next_input)
        block_result = b''
        for i in range(len(block)):
            block_result += bytes([encrypted[i] ^ block[i]])
        next_input = block
        final_result += block_result
    
    return final_result.decode('utf-8')
    

def attackAESMode1(plaintext1: str, ciphertext1: bytes, plaintext2: str) -> bytes:
    # Conversion of plaintexts to bytes
    pt1_bytes = plaintext1.encode('utf-8')
    pt2_bytes = plaintext2.encode('utf-8')
    # This sort of attack is the known plain text attack, where the original plaintext and ciphertext is known. 
    # Using this as shown in the figure 3 of the briefing, the known plain text and cipher text can be used,
    # to exploit XOR properties to reveal the encryption/keystream.
    # which can be used to forge a a foreign encrypted message


    # This is to ensure that the ciphertext actually corresponds to the plaintext
    if len(ciphertext1) < len(pt1_bytes):
        raise ValueError("ciphertext1 must be at least as long as plaintext1")
    # Below forms the 16 byte encryptor, by XORing the plaintext and ciphertext, 
    #  to form the 16 byte encryptor. Which is then later used to encrypt another message.
    keystream = bytes([pt1_bytes[i] ^ ciphertext1[i] for  i in range(16)])

    final_result = b''  
    # In this for loop a byte by byte XOR operation occurs, XORing the corresponding value of the second plaintext,
    #  with the corresponding derived encryptor value, when reached above 16 byte, it'll wrap around and reuse the encryptor.
    for i in range(len(pt2_bytes)):
        final_result += bytes([pt2_bytes[i] ^ keystream[i % 16]])
    
    return final_result




def myHash(data: bytes) -> bytes:
    # Input data is first converted into a cryptographic digest, then is split into two hash,
    # by dividing. Then a for loop iterates till i reaches the length of half the size. 
    # Corresponding value of the first half is XOR'd with the second and values get added to the variable value_a,
    # for use later.
    initial_hash = sha256(data).digest()
    half_size = len(initial_hash) // 2
    half1 = initial_hash[:half_size]
    half2 = initial_hash[half_size:]

    value_a = b''
    for i in range(half_size):
        value_a += bytes([half1[i] ^ half2[i]])

    # value_a variable is used to split two hashes of 16 bytes. These hashes then are just like in the first loop,
    # XOR'd and their values are placed in value_b, this intention is to preserve the hash's values overall, while deliberately compressing.
    # The second reduction stage continues the compression, further reducing the information content of the original hash 

    half_value_a = len(value_a) // 2
    first_a = value_a[:half_value_a]
    second_a = value_a[half_value_a:]

    value_b = b''
    for i in range(half_value_a):
        value_b += bytes([first_a[i] ^ second_a[i]])

    # The final reduction stage culminates both previous resulting hash's value_a and value_b,
    # which goes through a final XOR to reduce the original size down to a 4 byte output

    half_value_b = len(value_b) // 2
    first_b = value_b[:half_value_b]
    second_b = value_b[half_value_b:]
    result_hash = b''

    for i in range(half_value_b):
        result_hash += bytes([first_b[i] ^ second_b[i]])
    # The final output represents the original cryptographic digest, in its most compressed form. 
    # This can show aggressive hash compression, can lead to a massive information loss.
    return result_hash

def myAttack() -> str:
    #This function is meant to help evaluate the cryptographic security of the myHash function by performing security tests.
    # Each test checks for a specific vulnerability, with any hint of failure indicating that,
    # the hash function is not cryptographically secure.
    
    #This is a basic collision test which basically performs a test on whether two different inputs can lead to the same hash value.
    #A cryptographically secure hash function should always produce distinct outputs for different inputs even if they're closely similar.
    input1 = b"_unlke_1"
    input2 = b"_unlke_2"
    hash1 = myHash(input1)
    hash2 = myHash(input2)
    if hash1 == hash2:
        return "NO"

    #This is a common bytes test which basically tests and checks on how many bytes are identifcal between two complete different hashes.
    #Having too many matching bytes more than 2 in this test case could indicate poor distribution of hash values.
    #For loop is ran in the length of a hash and in each iteration if the corresponding value of the first hash matches,
    # with the second hash it'll add one to the counter variable common_bytes. At the end if common_bytes exceed 2,

    input3 = b"another_different_3"
    input4 = b"another_different_4"
    hash3 = myHash(input3)
    hash4 = myHash(input4)
    common_bytes = 0

    for i in range(len(hash3)):
        if hash3[i] == hash4[i]:
            common_bytes += 1
    if common_bytes > 2:
        return "NO"

    #This is the avalanche effect test, this tests the avalanche effect.
    # The smallest change should cause a significant change in the output of the hash. It modifies a single bit in the input and counts how many bits,
    # change in the output hash. If the numbers of bits changed is low, this indicates poor distribution.
    # The threshold is 3 times the hash length in bits, forgoing the "massive output change for minimal input modification"

    base_input = b"test_string"
    base_hash = myHash(base_input)

    modified_input = bytearray(base_input)
    modified_input[0] ^= 1
    modified_hash = myHash(bytes(modified_input))

    bit_differences = 0

    for i in range(len(base_hash)):
        xor_result = base_hash[i] ^ modified_hash[i]
        binary_str = bin(xor_result)[2:]
        bit_differences += binary_str.count('1')
    if bit_differences < len(base_hash) * 3:
        return "NO"

    # This is the birthday attack, its an if statement that calls on a birthday_attack function.
    # The birthday attack function randomly creates a 16 byte data which gets placed as a parameter in the myHash function. 
    # The value of return from myHash is stored in the variable hash_value, 
    # 
    # This will continue to loop in a while loop over 100000 iterations, storing every new data in collisions,
    #  until either the data already exists, in which it will return back a boolean value of True outputting a NO,
    #  or it exceeds 100,000 without finding the same value in which it will return False and pass without a "NO".
    # 
    # The premise of the birthday attack exploits "the birthday paradox", which states that,
    #  in a group of 23 people, there is a about 50% chance that two will share the exact same birthday.
    # 
    # In the same case here, because we're using a 32-bit hash function, mathematically on average we expect 
    #  to find identical hashes around at 65,536.

    if birthday_attack():
        return "NO"
    

    #The function only returns YES if all security tests pass.
    #Any single failure indicates the function is not cryptographically secure.
    return "YES"

# Main
if __name__ == "__main__":
    print(myHash(b"a"))
    result = myAttack()
    print(f"\nFinal Result: {result}")
