#! /usr/bin/env python
# coding: utf-8
from __future__ import print_function
import argparse
from libs.encrypt import RSA_Cipher, RSA_Decipher, AES_Cipher

import sys, io
import os
import textwrap


def set_io_utf8():
    if sys.stdout.encoding.lower() != 'utf-8':
        #print('change stdout encoding from %s to utf-8' % sys.stdout.encoding)
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    if sys.stdin.encoding.lower() != 'utf-8':
        #print('change stdin encoding from %s to utf-8' % sys.stdin.encoding)
        sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')


def get_input_bytes(file):
    input_text = file.read()
    if not isinstance(input_text, bytes):
        input_text = input_text.encode()
    return input_text

def cmd_rsa_encrypt(args):
    input_text = get_input_bytes(args.infile)
    encryptor = RSA_Cipher(args.key)
    if args.outfile:
        encrypted_text = encryptor.encrypt(input_text)
        args.outfile.write(encrypted_text)
    else:
        encrypted_text = encryptor.encrypt_b64(input_text)
        print(encrypted_text.decode())

def cmd_rsa_decrypt(args):
    input_text = get_input_bytes(args.infile)
    decryptor = RSA_Decipher(args.key, args.passphrase)
    try:
        decrypted_text = decryptor.decrypt_b64(input_text)
    except ValueError:
        decrypted_text = decryptor.decrypt(input_text)
    
    if args.outfile:
        args.outfile.write(decrypted_text)
    else:
        print(decrypted_text.decode())

def cmd_aes_encrypt(args):
    input_text = get_input_bytes(args.infile)
    aes = AES_Cipher(args.password.encode(), key_align=args.key_size)
    if args.outfile:
        crypt_text = aes.encrypt(input_text)
        args.outfile.write(crypt_text)
    else:
        crypt_text = aes.encrypt_b64(input_text)
        print(crypt_text.decode())

def cmd_aes_decrypt(args):
    input_text = get_input_bytes(args.infile)
    aes = AES_Cipher(args.password.encode(), key_align=args.key_size)

    try:
        crypt_text = aes.decrypt_b64(input_text)
    except ValueError:
        crypt_text = aes.decrypt(input_text)

    if args.outfile:
        args.outfile.write(crypt_text)
    else:
        print(crypt_text.decode())


def main():
    set_io_utf8()

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
        Simple utility for RSA/AES encryption and decryption.

        If option -o is not givent, the encrypted data with base64 encoding
        is printed to console.

        If not specify input file, data to encrypt/decrypt is read from
        standard input until EOF (Linux:Ctrl-D, Windows: Ctrl-Z + ENTER)
        '''),
        epilog=textwrap.dedent('''\
        Examples of usage:
            1. RSA
                1. encryption using default public key
                $ ./%(prog)s rsa-e filename > encrypted.txt
                $ ./%(prog)s rsa-e filename -o encrypted.bin
                $ echo abcd | ./%(prog)s rsa-e > encrypted.txt

                2. encryption using specific private/public key
                $ ./%(prog)s rsa-e filename -k ./id_rsa.pub -o encrypted.bin

                3. decryption using default private key
                $ ./%(prog)s rsa-d encrypted.txt
                $ ./%(prog)s rsa-d encrypted.bin -o decrypted.file

                4. decryption using specific private key
                $ ./%(prog)s rsa-d -k ./id_rsa encrypted.txt
            2. AES
                1. encrypt to a file
                $ ./%(prog)s aes-e --password 12345678 filename -o encrypted.file

                2. decrypt to file
                $ ./%(prog)s aes-d --password 12345678 encrypted.file -o decrypted.file

                3. encrypt to console
                $ echo abcd | ./%(prog)s aes-e --password 12345678

                4. decrypt to console
                $ echo LwkjmQ7Vg8fRB01NFk7RrA== | ./%(prog)s aes-d --password 12345678
        ''')
        )
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1')

    subparsers = parser.add_subparsers(title='List of Commands', metavar='')
    parser_rsa_en = subparsers.add_parser('rsa-e', description='RSA encryption', help='RSA encryption')
    parser_rsa_de = subparsers.add_parser('rsa-d', description='RSA decryption', help='RSA decryption')
    parser_aes_en = subparsers.add_parser('aes-e', description='AES encryption', help='AES encryption')
    parser_aes_de = subparsers.add_parser('aes-d', description='AES decryption', help='AES decryption')

    parser_rsa_en.add_argument("infile", metavar='INPUT_FILE', nargs='?', type=argparse.FileType('rb'), default=sys.stdin, help='input file to encrypt (default: stdin)')
    parser_rsa_en.add_argument('-k', '--key', default='~/.ssh/id_rsa.pub', help='RSA public/private key (default: %(default)s)' )
    parser_rsa_en.add_argument('-o', dest='outfile', metavar='OUTPUT_FILE', type=argparse.FileType('wb'), help='output file in binary format' )
    parser_rsa_en.set_defaults(func=cmd_rsa_encrypt)

    parser_rsa_de.add_argument("infile", metavar='INPUT_FILE', nargs='?', type=argparse.FileType('rb'), default=sys.stdin, help='input file to decrypt (default: stdin)')
    parser_rsa_de.add_argument('-k', '--key', default='~/.ssh/id_rsa', help='RSA private key (default: %(default)s)' )
    parser_rsa_de.add_argument('-p', dest='passphrase', default=None, help='passphrase for RSA private key, default is empty')
    parser_rsa_de.add_argument('-o', dest='outfile', metavar='OUTPUT_FILE', type=argparse.FileType('wb'), help='output file in binary format' )
    parser_rsa_de.set_defaults(func=cmd_rsa_decrypt)

    parser_aes_en.add_argument("infile", metavar='INPUT_FILE', nargs='?', type=argparse.FileType('rb'), default=sys.stdin, help='input file to encrypt (default: stdin)')
    parser_aes_en.add_argument('-p', '--password', default='12345678', help='password for AES encryption (default: %(default)s)')
    parser_aes_en.add_argument('-o', dest='outfile', metavar='OUTPUT_FILE', type=argparse.FileType('wb'), help='output file in binary format' )
    parser_aes_en.add_argument('--key-size', type=int, default=32, choices=[16, 24, 32], help='key size in bytes (default: %(default)sbytes)')
    parser_aes_en.set_defaults(func=cmd_aes_encrypt)

    parser_aes_de.add_argument("infile", metavar='INPUT_FILE', nargs='?', type=argparse.FileType('rb'), default=sys.stdin, help='input file to decrypt (default: stdin)')
    parser_aes_de.add_argument('-p', '--password', default='12345678', help='password for AES decryption (default: %(default)s)')
    parser_aes_de.add_argument('-o', dest='outfile', metavar='OUTPUT_FILE', type=argparse.FileType('wb'), help='output file in binary format' )
    parser_aes_de.add_argument('--key-size', type=int, default=32, choices=[16, 24, 32], help='key size in bytes (default: %(default)sbytes)')
    parser_aes_de.set_defaults(func=cmd_aes_decrypt)

    args = parser.parse_args()
    try:
        args.func(args)
    except AttributeError:
        parser.print_help()


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(e)
        raise
        sys.exit(1)
    

