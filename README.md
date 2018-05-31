simple TCP Server/Client model to simulate ssh
==============================

Table of Contents
+ [porpuse](#porpuse)
+ [preparation](#preparation)
+ [example](#example)
    + [RSA](#RSA)
    + [AES](#AES)

## porpuse
simple utility for RSA/AES encryption and decryption.

## preparation
1. requires Python 3.5 or newer version
1. requires 3rd-party modules, e.g. pycryptodome
    ```
    pip install -r equirements.txt
    ```
1. generate RSA key pair: id_rsa (priviate key) and  id_rsa.pub (public key)
    ```
    ssh-keygen -t rsa -C "your-comments"
    ls ~/.ssh
    $ authorized_keys  id_rsa  id_rsa.pub  known_hosts
    ```
1. register public key to ~/.ssh/authorized_keys in remote host
    ```
    ssh-copy-id -i id_rsa.pub root@192.168.56.111
    ```


## example
### RSA
#### encryption using default public key (~/.ssh/id_rsa.pub)
``` bash
# encrypt string from pipe
$ echo abcd | ./cipher.py rsa-e
lRMjlpn0DMd1yBAPz888A+dxsBy6dJ6IjIPe5h+sZ/Hwgu+8z8a75iEJabYEsFFsi3e11ffB0pKikMCPY+NqknqkRz6eQBaM9AMrgDkI088L81mTD4YT+LCgGWqZvDA+xLy4sSkx+B78ASVEWYAWwDxra3A/HJ/WQE+TR05rZq7ufcbY7b5aztVNjFYvv1aiAyjd6KQl6bzBdD2uJlfinKkgnBKdeciePKI3pNmUVQlW7Cwiwy8QSqgx/ldNHekUt+IWdUN1AL1ISJpFFpOpTSXBgu+BSPqBxb5Erc4FRP0p8OiYdZ7tF8fj2RRLy2AlQkrDpH1AC/cRKOw33T+1wA==

# encrypt string from pipe
$ echo abcd | ./cipher.py rsa-e > encrypted_text

# encrypt a file
$ ./cipher.py rsa-e test.txt
cw/3rm/jFvhLm3NBgxGXocze6KFdX3vcVVxiRLI7/dXWd2R0WyvuRpbZgPZ1Y8JxZWAF+vSDO9B5aOcodPCdARUAbWQqomy8rwzw8X7HNU7EHsEF6AIoNRrJYEG1ZWjURh8fn6i/85zTS4W7OnOxkYGrTt/lADDoFq3I1Q4BcZt/q+6E+KtOPGekxXTHC1jH3ZVntTo0xuc5puJpTkS0WuKLHlh+gMMv0USq3XUmRH3U8onS/1dMBSAfIEcfNHFBgDAnKwszDS/ABnJCt3wfdQpRq8o4gk+3yDFHX8HFTQWi6RAa9ClyFjdIvQK1gJDDmejEzGpe554loRPF733l6w==

```

#### decryption using default private key (~/.ssh/id_rsa)
``` bash
# decrypt string from pipe
$ cat encrypted_text | ./cipher.py rsa-d
abcd

# decrypt a file
$ ./cipher.py rsa-d encrypted_text
abcd
```

#### encryption using specific private/public key
``` bash
$ echo abcd | cipher.py rsa-e -k ./id_rsa.pub > encrypted_text
```

#### decryption using specific private key
``` bash
$ cat encrypted_text | ./cipher.py rsa-d -k ./id_rsa
abcd
```

### AES
TBD