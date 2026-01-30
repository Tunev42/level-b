import hashlib


def vigenere_encrypt(text, key):
    result = ""
    key = key.upper()
    key_len = len(key)

    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % key_len]) - ord('A')
            if char.isupper():
                new_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                new_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            result += new_char
        else:
            result += char
    return result



input_file = "input.txt"
signature_file = "signature.txt"
key = "KEY"

with open(input_file, "r") as f:
    data = f.read()
hash_hex = hashlib.sha256(data.encode()).hexdigest()


encrypted_hash = vigenere_encrypt(hash_hex, key)

with open(signature_file, "w") as f:
    f.write(encrypted_hash)

print("Подпись создана!")