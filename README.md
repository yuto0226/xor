# XOR

A python script for xor encryption/decryption

```
usage: xor.py [-h] [-c CONTENT] [-f FILE] [-k KEY] [-o OUTPUT] [--hex-content] [--hex-key]

XOR encryption/decryption script

options:
  -h, --help            show this help message and exit
  -c CONTENT, --content CONTENT
                        Content to be encrypted/decrypted
  -f FILE, --file FILE  File path to read content from
  -k KEY, --key KEY     Encryption/Decryption key
  -o OUTPUT, --output OUTPUT
                        File path to save the result
  --hex-content         Interpret content as a hexadecimal string
  --hex-key             Interpret key as a hexadecimal string

Examples:
  Encrypt a string:
    xor.py -c "Hello, World!" -k "mysecretkey"

  Decrypt a string:
    xor.py -c "<hex_content>" -k "mysecretkey" --hex-content

  Encrypt a file:
    xor.py -f input.txt -k "mysecretkey" -o output.txt

  Decrypt a file:
    xor.py -f encrypted.bin -k "mysecretkey" -o decrypted.txt

  Use hexadecimal key:
    xor.py -c "Hello, World!" -k "6d797365637265746b6579" --hex-key
```
