#!/bin/python3
import sys
import argparse

# XOR function
def xor(data, key):
    """
    Perform XOR operation on data with the given key.
    The key is repeated or truncated to match the length of the data.
    """
    key = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytearray(a ^ b for a, b in zip(data, key))

def hex_to_bytes(hex_str):
    """
    Convert a hexadecimal string to bytes.
    Raise a ValueError if the string is not valid hexadecimal.
    """
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        print(f"[-] Error: Invalid hex string '{hex_str}'. {e}")
        sys.exit(1)

def read_content(args):
    """
    Read the content from the command line or file, based on the provided arguments.
    """
    if args.content:
        return hex_to_bytes(args.content) if args.hex_content else args.content.encode()
    if args.file:
        try:
            with open(args.file, "rb") as f:
                return f.read()
        except FileNotFoundError:
            print(f"[-] Error: File '{args.file}' not found.")
            sys.exit(1)
    print("[-] Error: Either content (-c) or file (-f) must be provided.")
    sys.exit(1)

def prepare_key(args):
    """
    Prepare the encryption/decryption key, converting it from hexadecimal if required.
    """
    if args.key:
        return hex_to_bytes(args.key) if args.hex_key else args.key.encode()
    print("[-] Error: A key (-k) must be provided.")
    sys.exit(1)

def save_result(result, output_path):
    """
    Save the XOR result to the specified file or print it to the console.
    """
    if output_path:
        try:
            with open(output_path, "wb") as f:
                f.write(result)
            print(f"[+] Result saved to '{output_path}'.")
        except IOError as e:
            print(f"[-] Error writing to file '{output_path}': {e}")
            
    print("[+] Result:")
    print(result.decode(errors="ignore"))  # Decode for readability, ignoring errors

def main():
    parser = argparse.ArgumentParser(
        description="XOR encryption/decryption script",
        epilog="""
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
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-c", "--content", type=str, help="Content to be encrypted/decrypted")
    parser.add_argument("-f", "--file", type=str, help="File path to read content from")
    parser.add_argument("-k", "--key", type=str, help="Encryption/Decryption key")
    parser.add_argument("-o", "--output", type=str, help="File path to save the result")
    parser.add_argument("--hex-content", action="store_true", help="Interpret content as a hexadecimal string")
    parser.add_argument("--hex-key", action="store_true", help="Interpret key as a hexadecimal string")
    args = parser.parse_args()

    data = read_content(args)
    key = prepare_key(args)
    result = xor(data, key)
    save_result(result, args.output)

if __name__ == "__main__":
    main()
