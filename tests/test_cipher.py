# coding: utf-8

import os
import sys

CUR_DIR = os.path.abspath(os.path.dirname(__file__))
SRC_DIR = os.path.abspath(os.path.join(CUR_DIR, '..'))
sys.path.insert(0, SRC_DIR)

from cipher import main

import unittest

from subprocess import PIPE, Popen, STDOUT, TimeoutExpired

CIPHER = 'python ' + SRC_DIR + os.sep + 'cipher.py '


def exe_cmd(cmd, timeout=10):
    '''
    execute command.
    return output, errcode
    '''
    process = Popen(cmd, stdout=PIPE, stderr=STDOUT, shell=True)
    try:
        outs = process.communicate(timeout=timeout)[0]
    except TimeoutExpired:
        process.terminate()
        process.communicate()
        outs = cmd.encode() + b': command timeouted\n'

    err = process.returncode
    # print(err, cmd, outs)
    return outs, err


class Test_AES(unittest.TestCase):
    def setUp(self):
        os.chdir(CUR_DIR)

    def tearDown(self):
        exe_cmd('rm -rf encrypted.* outfile')

    def test_AES_txt_default_psw(self):
        __, err = exe_cmd(CIPHER + 'aes-e long.txt > encrypted.txt')
        self.assertEqual(err, 0)

        __, err = exe_cmd(CIPHER + 'aes-d encrypted.txt -o outfile')
        self.assertEqual(err, 0)

        __, err = exe_cmd('diff long.txt outfile')
        self.assertEqual(err, 0)

    def test_AES_bin_default_psw(self):
        __, err = exe_cmd(CIPHER + 'aes-e ls.exe > encrypted.txt')
        self.assertEqual(err, 0)

        __, err = exe_cmd(CIPHER + 'aes-d encrypted.txt -o outfile')
        self.assertEqual(err, 0)

        __, err = exe_cmd('diff ls.exe outfile')
        self.assertEqual(err, 0)

    def test_AES_txt_psw(self):
        password = 'ABCDE1234'
        __, err = exe_cmd(CIPHER + 'aes-e -p %s long.txt > encrypted.txt' % password)
        self.assertEqual(err, 0)
        
        __, err = exe_cmd(CIPHER + 'aes-d -p %s encrypted.txt -o outfile' % password)
        self.assertEqual(err, 0)

        __, err = exe_cmd('diff long.txt outfile')
        self.assertEqual(err, 0)

    def test_AES_bin_psw(self):
        password = 'ABCDE1234abc'
        __, err = exe_cmd(CIPHER + 'aes-e -p %s ls.exe > encrypted.txt' % password)
        self.assertEqual(err, 0)

        __, err = exe_cmd(CIPHER + 'aes-d -p %s encrypted.txt -o outfile' % password)
        self.assertEqual(err, 0)

        __, err = exe_cmd('diff ls.exe outfile')
        self.assertEqual(err, 0)

    def test_AES_option_o(self):
        password = 'ABCDE1234abc'
        __, err = exe_cmd(CIPHER + 'aes-e -p %s ls.exe -o encrypted.bin' % password)
        self.assertEqual(err, 0)

        __, err = exe_cmd(CIPHER + 'aes-d -p %s encrypted.bin -o outfile' % password)
        self.assertEqual(err, 0)

        __, err = exe_cmd('diff ls.exe outfile')
        self.assertEqual(err, 0)


class Test_RSA(unittest.TestCase):
    def setUp(self):
        os.chdir(CUR_DIR)

    def tearDown(self):
        exe_cmd('rm -rf encrypted.* outfile')

    def test_RSA_with_default_key(self):
        __, err = exe_cmd(CIPHER + 'rsa-e short.txt > encrypted.txt')
        self.assertEqual(err, 0)

        __, err = exe_cmd(CIPHER + 'rsa-d encrypted.txt -o outfile')
        self.assertEqual(err, 0)

        __, err = exe_cmd('diff short.txt outfile')
        self.assertEqual(err, 0)

    def test_RSA_with_echo(self):
        text = 'abcdefg12345ABCD'
        __, err = exe_cmd('echo ' + text + '|' + CIPHER + 'rsa-e -k keys/test_rsa.pub > encrypted.txt')
        self.assertEqual(err, 0)

        outs, err = exe_cmd(CIPHER + 'rsa-d -k keys/test_rsa encrypted.txt')
        self.assertEqual(err, 0)
        self.assertEqual(text, outs.decode().strip())

    def test_RSA_with_cat(self):
        __, err = exe_cmd('cat short.txt | ' + CIPHER + 'rsa-e -k keys/test_rsa.pub > encrypted.txt')
        self.assertEqual(err, 0)

        __, err = exe_cmd(CIPHER + 'rsa-d -k keys/test_rsa encrypted.txt -o outfile')
        self.assertEqual(err, 0)

        __, err = exe_cmd('diff short.txt outfile')
        self.assertEqual(err, 0)

    def test_RSA_with_key(self):
        __, err = exe_cmd(CIPHER + 'rsa-e -k keys/test_rsa.pub short.txt -o encrypted.bin')
        self.assertEqual(err, 0)

        __, err = exe_cmd(CIPHER + 'rsa-d -k keys/test_rsa encrypted.bin -o outfile')
        self.assertEqual(err, 0)

        __, err = exe_cmd('diff short.txt outfile')
        self.assertEqual(err, 0)

    def test_RSA_with_option_o(self):
        __, err = exe_cmd(CIPHER + 'rsa-e -k keys/test_rsa.pub short.txt -o encrypted.bin')
        self.assertEqual(err, 0)

        __, err = exe_cmd(CIPHER + 'rsa-d -k keys/test_rsa encrypted.bin -o outfile')
        self.assertEqual(err, 0)

        __, err = exe_cmd('diff short.txt outfile')
        self.assertEqual(err, 0)