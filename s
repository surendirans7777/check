import hashlib

def sha256_hex(string1, string2):
    concatenated_string = string1 + string2
    hash_object = hashlib.sha256(concatenated_string.encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig

# Take input from the user
input1 = input("Enter the first string: ")
input2 = input("Enter the second string: ")

# Perform SHA-256 hashing and print the hexadecimal representation
result = sha256_hex(input1, input2)
print("SHA-256 hex digest:", result)
