import argparse
import os
import struct
import sys
import hmac
import unicodedata
from getpass import getpass
from pathlib import Path
from timeit import default_timer as timer

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

# Security constants
MAX_FILENAME_LENGTH = 255
MIN_PASSWORD_LENGTH = 12
PBKDF2_ITERATIONS = 1_200_000

def constant_time_compare(val1, val2):
    """Timing-attack safe value comparison"""
    return hmac.compare_digest(val1, val2)

def secure_filename(filename):
    """Sanitize and normalize filenames to prevent path injection"""
    filename = unicodedata.normalize('NFKC', filename)
    filename = ''.join(c for c in filename if c.isprintable() and c not in '/\\:*?"<>|')
    filename = filename.strip().lstrip('.')
    return filename[:MAX_FILENAME_LENGTH]

def secure_delete(path, passes=3):
    """Securely erase file contents before deletion"""
    try:
        with open(path, 'br+') as f:
            length = f.tell()
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
        os.remove(path)
    except Exception:
        pass

def derive_key(password, salt, iterations):
    """Key derivation with parameter validation"""
    if len(salt) != 16:
        raise ValueError("Invalid salt length")
    if iterations < 100_000:
        raise ValueError("Insufficient PBKDF2 iterations")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8', 'strict'))

def encrypt_file(input_path, output_path, password, iterations):
    """Secure file encryption with authenticated encryption"""
    try:
        input_file = Path(input_path)
        if not input_file.is_file():
            raise ValueError("Input file not found")

        # Generate cryptographic components
        salt = os.urandom(16)
        nonce = os.urandom(12)
        filename = secure_filename(input_file.name)
        filename_bytes = filename.encode('utf-8', 'strict')

        # Read and package payload
        with input_file.open('rb') as f:
            file_data = f.read()
        payload = struct.pack('>I', len(filename_bytes)) + filename_bytes + file_data

        # Key derivation
        key = derive_key(password, salt, iterations)

        # Perform encryption
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(payload) + encryptor.finalize()
        tag = encryptor.tag

        # Secure file writing
        try:
            fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(salt)
                f.write(struct.pack('>I', iterations))
                f.write(nonce)
                f.write(tag)
                f.write(ciphertext)
        except FileExistsError:
            raise ValueError("Output file already exists - use unique filename")

    except Exception as e:
        if 'output_path' in locals() and Path(output_path).exists():
            secure_delete(output_path)
        raise e

def decrypt_file(input_path, output_path, password):
    """Secure file decryption with integrity verification"""
    try:
        input_file = Path(input_path)
        if not input_file.is_file():
            raise ValueError("Input file not found")

        # Read header components
        with input_file.open('rb') as f:
            header = f.read(48)
            if len(header) != 48:
                raise ValueError("Invalid file header structure")
            
            salt, iter_bytes, nonce, tag = header[:16], header[16:20], header[20:32], header[32:48]
            iterations = struct.unpack('>I', iter_bytes)[0]
            ciphertext = f.read()

        # Key derivation
        key = derive_key(password, salt, iterations)

        # Initialize cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # Process in chunks for memory efficiency
        decrypted = bytearray()
        chunk_size = 4096
        for i in range(0, len(ciphertext), chunk_size):
            decrypted.extend(decryptor.update(ciphertext[i:i+chunk_size]))
        decrypted.extend(decryptor.finalize())

        # Extract metadata
        if len(decrypted) < 4:
            raise ValueError("Corrupted data payload")
        
        filename_len = struct.unpack('>I', decrypted[:4])[0]
        if filename_len > MAX_FILENAME_LENGTH or (4 + filename_len) > len(decrypted):
            raise ValueError("Invalid metadata structure")
        
        filename = secure_filename(decrypted[4:4+filename_len].decode('utf-8', 'strict'))
        content = decrypted[4+filename_len:]

        # Determine output path
        output_dir = Path(output_path) if output_path else Path.cwd()
        if output_dir.is_dir():
            output_file = output_dir / filename
        else:
            output_file = Path(output_path)

        # Prevent file overwrite
        counter = 1
        base = output_file.stem
        ext = output_file.suffix
        while output_file.exists():
            output_file = output_file.with_name(f"{base}_{counter}{ext}")
            counter += 1

        # Write decrypted content
        try:
            fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(content)
        except FileExistsError:
            raise ValueError("Output file already exists - check destination")

        return output_file

    except (InvalidTag, ValueError) as e:
        raise ValueError("Decryption failed: invalid ciphertext or incorrect password")

def main():
    parser = argparse.ArgumentParser(
        description='Secure File Encryption Tool (AES-256-GCM)',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''Examples:
  Encrypt with password file: encrypt -i data.txt -p "$(cat pass.txt)"
  Decrypt interactively: decrypt -i data.enc -o decrypted/
  
Security Best Practices:
  - Use strong passwords (12+ characters, mixed types)
  - Never store passwords in plain text
  - Use password files instead of command-line arguments
  - Verify encrypted file integrity before deletion'''
    )

    subparsers = parser.add_subparsers(dest='command', required=True)

    # Encryption command
    enc_parser = subparsers.add_parser('encrypt', help='Encrypt a file', formatter_class=argparse.RawTextHelpFormatter)
    enc_parser.add_argument('-i', '--input', required=True,
                          help='Input file to encrypt (required)')
    enc_parser.add_argument('-o', '--output',
                          help='Output file path (default: <input>.enc)')
    enc_parser.add_argument('-p', '--password',
                          help='''Encryption password (use with caution)
Warning: Command-line passwords may be exposed in:
- Shell history
- Process listings
- System logs
Recommended: -p "$(cat password_file)"''')
    enc_parser.add_argument('--iterations', type=int, default=PBKDF2_ITERATIONS,
                          help=f'PBKDF2 iterations (default: {PBKDF2_ITERATIONS:,})')

    # Decryption command
    dec_parser = subparsers.add_parser('decrypt', help='Decrypt a file', formatter_class=argparse.RawTextHelpFormatter)
    dec_parser.add_argument('-i', '--input', required=True,
                          help='Input file to decrypt (required)')
    dec_parser.add_argument('-o', '--output',
                          help='Output path (file or directory)')
    dec_parser.add_argument('-p', '--password',
                          help='''Decryption password
Recommended: -p "$(cat password_file)"''')

    args = parser.parse_args()

    try:
        if args.command == 'encrypt':
            # Password handling
            if args.password:
                if len(args.password) < MIN_PASSWORD_LENGTH:
                    print(f"Error: Password must be at least {MIN_PASSWORD_LENGTH} characters")
                    sys.exit(1)
                password = args.password
            else:
                while True:
                    password = getpass("Encryption password: ")
                    if len(password) < MIN_PASSWORD_LENGTH:
                        print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
                        continue
                    confirm = getpass("Confirm password: ")
                    if constant_time_compare(password, confirm):
                        break
                    print("Error: Password mismatch")

            output = args.output or f"{args.input}.enc"
            start = timer()
            encrypt_file(args.input, output, password, args.iterations)
            print(f"Success: Encrypted to {output} in {timer()-start:.2f}s")

        elif args.command == 'decrypt':
            # Password handling
            password = args.password or getpass("Decryption password: ")
            
            start = timer()
            output = decrypt_file(args.input, args.output, password)
            print(f"Success: Decrypted to {output} in {timer()-start:.2f}s")

    except Exception as e:
        print(f"Critical Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
