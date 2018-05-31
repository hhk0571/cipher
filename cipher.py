#! /usr/bin/env python
# coding: utf-8
from __future__ import print_function
import argparse
from libs.encrypt import RSA_Encryptor, RSA_Decryptor, AES_Encryptor, get_random_str

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


def get_input_text(file):
    input_text = file.read()
    if file is sys.stdin:
        input_text = input_text[:-1]
    return input_text

def cmd_rsa_encrypt(args):
    input_text = get_input_text(args.infile)
    encryptor = RSA_Encryptor(args.key)
    encrypted_text = encryptor.encrypt_b64(input_text.encode())
    print(encrypted_text.decode())

def cmd_rsa_decrypt(args):
    input_text = get_input_text(args.infile)
    decryptor = RSA_Decryptor(args.key, args.passphrase)
    decrypted_text = decryptor.decrypt_b64(input_text.encode())
    print(decrypted_text.decode())

def cmd_aes_encrypt(args):
    input_text = get_input_text(args.infile)
    aes = AES_Encryptor(args.password.encode(), key_align=args.key_size)
    crypt_text = aes.encrypt_b64(input_text.encode())
    print(crypt_text.decode())

def cmd_aes_decrypt(args):
    input_text = get_input_text(args.infile)
    aes = AES_Encryptor(args.password.encode(), key_align=args.key_size)
    crypt_text = aes.decrypt_b64(input_text.encode())
    print(crypt_text.decode())


def main():
    set_io_utf8()

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
        Simple utility for RSA/AES encryption and decryption.
        The encrypted text is encoded with base64.
        If not specify target file, text to be encrypted/decrypted is read from
        standard input until EOF (Linux:Ctrl-D, Windows: Ctrl-Z + ENTER)
        '''),
        epilog=textwrap.dedent('''\
        Examples of usage:
            1. encryption using default private key
                echo abcd | %(prog)s rsa-e > encrypted_text
                cat a.txt | %(prog)s rsa-e > encrypted_text

            2. encryption using specific private/public key
                echo abcd | %(prog)s rsa-e -k ./id_rsa.pub > encrypted_text

            3. decryption using default private key
                cat encrypted_text | %(prog)s rsa-d

            4. decryption using specific private key
                cat encrypted_text | %(prog)s rsa-d -k ./id_rsa
        ''')
        )
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1')

    subparsers = parser.add_subparsers(title='List of Commands', metavar='')
    parser_rsa_en = subparsers.add_parser('rsa-e', description='RSA encryption', help='RSA encryption')
    parser_rsa_de = subparsers.add_parser('rsa-d', description='RSA decryption', help='RSA decryption')
    parser_aes_en = subparsers.add_parser('aes-e', description='AES encryption', help='AES encryption')
    parser_aes_de = subparsers.add_parser('aes-d', description='AES decryption', help='AES decryption')

    parser_rsa_en.add_argument("infile", metavar='FILE', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help='the target file to be encrypted')
    parser_rsa_en.add_argument('-k', '--key', default='~/.ssh/id_rsa.pub', help='RSA public/private key (default: %(default)s)' )
    parser_rsa_en.set_defaults(func=cmd_rsa_encrypt)

    parser_rsa_de.add_argument("infile", metavar='FILE', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help='the target file to be decrypted')
    parser_rsa_de.add_argument('-k', '--key', default='~/.ssh/id_rsa', help='RSA private key (default: %(default)s)' )
    parser_rsa_de.add_argument('-p', dest='passphrase', default=None, help='passphrase for RSA private key, default is empty')
    parser_rsa_de.set_defaults(func=cmd_rsa_decrypt)

    parser_aes_en.add_argument("infile", metavar='FILE', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help='the target file to be encrypted')
    parser_aes_en.add_argument('-p', '--password', default='12345678', help='password for AES encryption (default: %(default)s)')
    parser_aes_en.add_argument('--key-size', type=int, default=32, choices=[16, 24, 32], help='key size in bytes (default: %(default)sbytes)')
    parser_aes_en.set_defaults(func=cmd_aes_encrypt)

    parser_aes_de.add_argument("infile", metavar='FILE', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help='the target file to be decrypted')
    parser_aes_de.add_argument('-p', '--password', default='12345678', help='password for AES decryption (default: %(default)s)')
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
        sys.exit(1)
    

