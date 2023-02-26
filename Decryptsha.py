#!/usr/bin/env python3
import hashlib
import hmac

def decrypt_md5(hash_string):
    """Decrypt the MD5 hash string using hashlib"""
    md5 = hashlib.md5()
    md5.update(hash_string.encode('utf-8'))
    return md5.hexdigest()

def decrypt_sha1(hash_string):
    """Decrypt the SHA1 hash string using hmac"""
    sha1 = hmac.new(b'secret-key', hash_string.encode('utf-8'), hashlib.sha1)
    return sha1.hexdigest()

def decrypt_sha224(hash_string):
    """Decrypt the SHA224 hash string using hashlib"""
    sha224 = hashlib.sha224()
    sha224.update(hash_string.encode('utf-8'))
    return sha224.hexdigest()

def decrypt_sha256(hash_string):
    """Decrypt the SHA256 hash string using hashlib"""
    sha256 = hashlib.sha256()
    sha256.update(hash_string.encode('utf-8'))
    return sha256.hexdigest()

def decrypt_sha384(hash_string):
    """Decrypt the SHA384 hash string using hashlib"""
    sha384 = hashlib.sha384()
    sha384.update(hash_string.encode('utf-8'))
    return sha384.hexdigest()

def decrypt_sha512(hash_string):
    """Decrypt the SHA512 hash string using hashlib"""
    sha512 = hashlib.sha512()
    sha512.update(hash_string.encode('utf-8'))
    return sha512.hexdigest()

def display_menu():
    """Display the hash decryption menu"""
    print("Select the decryption method:")
    print("1. MD5")
    print("2. SHA1")
    print("3. SHA224")
    print("4. SHA256")
    print("5. SHA384")
    print("6. SHA512")

if __name__ == '__main__':
    hash_string = input("Enter the hash to be decrypted: ")
    display_menu()
    choice = input("Enter your choice: ")

    if choice == '1':
        print("Decrypted hash using MD5:", decrypt_md5(hash_string))
    elif choice == '2':
        print("Decrypted hash using SHA1:", decrypt_sha1(hash_string))
    elif choice == '3':
        print("Decrypted hash using SHA224:", decrypt_sha224(hash_string))
    elif choice == '4':
        print("Decrypted hash using SHA256:", decrypt_sha256(hash_string))
    elif choice == '5':
        print("Decrypted hash using SHA384:", decrypt_sha384(hash_string))
    elif choice == '6':
        print("Decrypted hash using SHA512:", decrypt_sha512(hash_string))
    else:
        print("Invalid choice. Please try again.")
