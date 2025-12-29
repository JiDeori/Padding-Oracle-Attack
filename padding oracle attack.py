import sys
from oracle_python_v1_2 import pad_oracle

BLOCK_SIZE = 8

def hex_to_bytes(hex_string):
    if hex_string.startswith('0x'):
        hex_string = hex_string[2:]
    else:
        print("Error: hex data must start with \'0x\'")
        sys.exit(1)

    return bytes.fromhex(hex_string)
    
def bytes_to_hex(byte_list):
    return '0x' + bytearray(byte_list).hex()

def remove_padding(plaintext_P):
    padding_length = plaintext_P[BLOCK_SIZE - 1]

    if padding_length == BLOCK_SIZE: 
        return plaintext_P
        
    return plaintext_P[0: (BLOCK_SIZE - padding_length)]

def convert_to_plaintext(plaintext_P, intermediate_I1, C0_bytes):
    for i in range(BLOCK_SIZE):
        plaintext_P[i] = intermediate_I1[i] ^ C0_bytes[i]

    message_bytes = remove_padding(plaintext_P)
    decrypted_message = bytes(message_bytes).decode('ascii')

    return decrypted_message


def pad_oracle_attack(C0_hex, C1_hex):

    intermediate_state_I1 = [0] * BLOCK_SIZE
    plaintext_P = [0] * BLOCK_SIZE
    C0_bytes = hex_to_bytes(C0_hex)

    for k in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - k
        modified_C0_bytes = [0] * BLOCK_SIZE
        
        for j in range(k + 1, BLOCK_SIZE):
            modified_C0_bytes[j] = intermediate_state_I1[j] ^ padding_value
        
        for guess in range(256):
            modified_C0_bytes[k] = guess
            modified_C0_hex = bytes_to_hex(modified_C0_bytes)

            ret = int(pad_oracle(modified_C0_hex, C1_hex))
            
            if ret == 1: # False-Positive 검증
                if k == BLOCK_SIZE - 1:
                    test_C0_bytes = list(modified_C0_bytes)
                    test_C0_bytes[k-1] ^= 0xFF
                    test_C0_hex = bytes_to_hex(test_C0_bytes)
                    
                    ret_false_positive = int(pad_oracle(test_C0_hex, C1_hex))
                    if ret_false_positive != 1:
                        continue  # False positive, 다음 guess 시도
                
                intermediate_state_I1[k] = guess ^ padding_value
                break
    
    message = convert_to_plaintext(plaintext_P, intermediate_state_I1, C0_bytes)

    return message

def main():
    if len(sys.argv) != 3:
        print("Error: 인자 갯수 오류")
        print("양식: 파일이름 C0 C1")
        sys.exit(1)
    
    C0_hex = sys.argv[1]
    C1_hex = sys.argv[2]
        
    plaintext = pad_oracle_attack(C0_hex, C1_hex)

    print(f"plaintext: {plaintext}")

if __name__ == "__main__":
    main()