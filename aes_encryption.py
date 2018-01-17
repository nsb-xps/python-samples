# AES Encryption in Python
# Author: Nachiket Bhoyar

import getopt
import sys

################################################################################
#
# Constants
#
################################################################################

S_BOX = [ 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01,
          0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D,
          0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
          0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
          0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7,
          0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
          0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E,
          0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
          0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
          0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB,
          0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
          0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
          0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C,
          0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
          0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
          0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
          0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3,
          0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
          0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A,
          0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
          0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
          0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9,
          0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9,
          0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
          0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99,
          0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        ]

R_CON = [ 0x01, 0x00, 0x00, 0x00,
          0x02, 0x00, 0x00, 0x00,
          0x04, 0x00, 0x00, 0x00,
          0x08, 0x00, 0x00, 0x00,
          0x10, 0x00, 0x00, 0x00,
          0x20, 0x00, 0x00, 0x00,
          0x40, 0x00, 0x00, 0x00,
          0x80, 0x00, 0x00, 0x00,
          0x1b, 0x00, 0x00, 0x00,
          0x36, 0x00, 0x00, 0x00
        ]

################################################################################
#
# Methods
#
################################################################################

def generate_key_schedule(cipher_key):
    ''' Takes the initial key and expands into 10 more keys to be used for
        11 total rounds '''

    if len(cipher_key) is not 16:
        print 'ERROR: Key length must be 16 characters (128 bits)'
        sys.exit(1)

    # Initialize key_schedule matrix to 0 and append initial key to it
    key_schedule = [[0x0 for c in range(44)] for r in range(4)]
    key_char_list = list(cipher_key)
    #for i in (0, len(key_char_list)):
        

    # FUTURE WORK: Accept variable length key
    # if key length is > 16 chars, then we use only the first 16 chars
    # and warn the user. If, key length < 16 chars, we append the key with 0s
    # to make it 16 chars.

    # Note, we need to add key in column-major order.
    index_ptr = 0

    for col in range(0, 4):
        for row in range(0, 4):
            key_schedule[row][col] = ord(key_char_list[index_ptr])
            index_ptr = index_ptr + 1

    col_ptr = 4
    while col_ptr < 44:
        if col_ptr % 4 is 0:
            ''' First column of a new round key '''
            # Rotate 1 word from last column of last key (col_ptr - 1) and save
            # it as current column
            key_schedule[0][col_ptr] = key_schedule[1][col_ptr - 1]
            key_schedule[1][col_ptr] = key_schedule[2][col_ptr - 1]
            key_schedule[2][col_ptr] = key_schedule[3][col_ptr - 1]
            key_schedule[3][col_ptr] = key_schedule[0][col_ptr - 1]

            # SubByte, XOR with RCon, XOR with (col_ptr - 4) column of the
            # key schedule
            for row in range(0,4):
                # We do 'logical &' with 0xFF to convert the char to a number
                # e.g.: 9a & FF = 1001 1010 & 1111 1111 = 1001 1010
                # Then we can operate on the number or use it as an index

                key_schedule[row][col_ptr] = (S_BOX[key_schedule[row][col_ptr] &
                                                    0xFF] & 0xFF) ^\
                                             (key_schedule[row][col_ptr-4] &
                                              0xFF) ^\
                                             (R_CON[(col_ptr-4)+row] & 0xFF)
        else:
            # XOR with (col_ptr - 4) column of the key schedule
            for row in range(0,4):
                key_schedule[row][col_ptr] = key_schedule[row][col_ptr-1] ^\
                                             key_schedule[row][col_ptr-4]
	col_ptr = col_ptr + 1

    return key_schedule


def encrypt_state(state, key_schedule, state_size):
    ''' Remember state is in Column Major order list.
        e.g. - element indices
        0  4   8  12
        1  5   9  13
        2  6  10  14
        3  7  11  15
    '''
    
    round_ctr = 0

    for i in range(state_size):
        state[i] = ord(state[i])
    
    # Initial round where we only add round key
    add_round_key(state, round_ctr, key_schedule)
    round_ctr = round_ctr + 1

    # Next 9 rounds
    while(round_ctr < 10):
            sub_bytes(state, state_size)
            shift_rows(state)
            mix_columns(state, state_size)
            add_round_key(state, round_ctr, key_schedule)
            round_ctr = round_ctr + 1

    # Final round with no MixColumns
    sub_bytes(state, state_size)
    shift_rows(state)
    add_round_key(state, round_ctr, key_schedule)

    for i in range(state_size):
        state[i] = chr(state[i])

def add_round_key(state, round_ctr, key_schedule):
    i = 0
    start_index = round_ctr * 4
    for c in range(start_index, start_index + 4):
        for r in range(4):
            state[i] = state[i] ^ key_schedule[r][c]
            i = i + 1


def sub_bytes(state, state_size):
    ''' Substitute bytes from S-Box'''
    for i in range(state_size):
	state[i]  = S_BOX[state[i] & 0xFF]


def shift_rows(state):
    ''' Cyclically shift elements in a row'''
    
    # Skip first row

    # Rotate by one in 2nd row (remember column-major order)
    temp = state[1]
    state[1] = state[5]
    state[5] = state[9]
    state[9] = state[13]
    state[13] = temp

    # Rotate by two in 3rd row
    temp = state[2]
    state[2] = state[10]
    state[10] = temp
    temp = state[6]
    state[6] = state[14]
    state[14] = temp

    # Rotate by three in 4th row
    temp = state[15]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = state[3]
    state[3] = temp


def mix_columns(state, state_size):
    ''' Matrix multiplication of state with Rijndael's Galois Field given below:
    |02  03  01  01|
    |01  02  03  01|
    |01  01  02  03| 
    |03  01  01  02|

    Multiplying by 02 is carried out by: char_multiply_by_2(state[i])
    Multiplying by 03 is carried out by: char_multiply_by_2(state[i]) XOR state[i]
    
    Refer the following document to understand the process -
    http://it352.files.wordpress.com/2012/02/20120111_mix_columns.pdf
    '''

    temp = []
    for i in range(0, state_size, 4):
            temp.append(char_multiply_by_2(state[i]) ^
                            char_multiply_by_2(state[i + 1]) ^ state[i + 1] ^
                            state[i + 2] ^ state[i + 3])
            temp.append(state[i] ^ char_multiply_by_2(state[i + 1]) ^
                            char_multiply_by_2(state[i + 2]) ^ state[i + 2] ^
                            state[i + 3])
            temp.append(state[i] ^ state[i + 1] ^
                            char_multiply_by_2(state[i + 2]) ^
                            char_multiply_by_2(state[i + 3]) ^ state[i + 3])
            temp.append(char_multiply_by_2(state[i]) ^ state[i] ^ state[i + 1] ^
                            state[i + 2] ^ char_multiply_by_2(state[i + 3]))

    for i in range(0, state_size):
            state[i] = temp[i]

		
def char_multiply_by_2(byte):
    ''' Multiplication by 2 for mix columns
        ref - http://it352.files.wordpress.com/2012/02/20120111_mix_columns.pdf
    '''
    # Multiply by 2 using bit shifting
    temp = byte << 1

    # Check for leading '1' in original byte which might be lost due to bit
    # left shift
    if (byte & 0x80) is not 0:
        # Python converts a hex number to decimal after bit shifting. We need to
        # make sure after the shift, we are left with 2 nibbles and not 3 which
        # might happen if there is a leading 1 in original byte.
        # For e.g.: 0xD4 (1101 0100)
        #   0xD4 << 1 = 424
        #   hex(424) = 0x1A8  <-- Extra leading nibble to carry the leading '1'

        # First, adjust last two nibbles to nullify the discrepancy caused by
        # leading '1' during bit shift
        # e.g.: 424  ^ 0x1B = 435
        temp = temp ^ 0x1B

        # Once, last two nibbles are adjusted, we don't need the leading nibble
        # with the '1' from left shift. So, truncate it.
        # e.g.: 435 & 0x0FF = 179
        #   hex(179) = 0xB3
        temp = temp & 0x0FF

    return temp

'''
FUTURE WORK:
Convert this existing parallel code from the CUDA AES Capstone Project to Python 
using Python parallel processing.

/*
GPU Kernel Function
*/
__global__ void kernelAES(char *pText, short *sBox, char *keySc, int totalSize,
                          char *cText) {
	// Calculate the state id on which a particular thread will work.
	int stateID = ((blockIdx.x * blockDim.x) + threadIdx.x)
	
	// Calculate state start index -
	// e.g. stateID of 0 --> start Index = 0 * 16 = 0
	int stateStartIdx = stateID * 16
	
	// Temporary state array so as to preserve original plain text 
	char state[16]
	if(stateStartIdx < totalSize) {
		for(int i = stateStartIdx i < stateStartIdx+16 i++) {
			//offset to 0-15 and copy plain text to temporary state
			state[i-stateStartIdx] = pText[i]		
		}
		int stateSize = 16
		
		encryptState(state, sBox, keySc, stateSize)

		for(int i = stateStartIdx; i < stateStartIdx+16; i++) {
			// Copy cipher text to cText
			cText[i] = state[i-stateStartIdx]
		}
	}
}
'''

def usage():
    print 'python aes_encryption.py <options>\n\n-h\t--help\n-f\t--file\
           Plaintext file name\n\
           \t\t (creates a sample file if this option is not specified)'
    print '-k\t--key\t\t 16 byte key (128-bits)'


def main(argv):

    # 128-bit key
    key = '1a25s8fe5dsg65ad'
    plain_text_file = ''
    
    # Handle commandline args
    try:                                
        opts, args = getopt.getopt(argv, 'hf:k:', ['help', 'file=', 'key='])
    except getopt.GetoptError:
        print 'Incorrect commandline option used\n'
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit()
        elif opt in ('-f', '--file'):
            plain_text_file = arg
        elif opt in ('-k', '--key'):
            key = arg

    # Create a sample plain text file if it is not defined by user
    if plain_text_file is '':
        plain_text_file = 'test_file.txt'
        with open(plain_text_file, 'w') as outfile:
            outfile.write('Hello Advanced Encryption Standard!')
        outfile.close()

    # Rijndael Key Expansion
    key_schedule = generate_key_schedule(key)

    '''# DEBUG KEYSCHEDULE
    for col in range(0,44):
        print col
        for row in range(0,4):
            print col, row, key_schedule[row][col], ','
        print ''
    '''
    
    plain_text = ''

    # Read plain text
    with open(plain_text_file, 'r') as infile:
        plain_text = infile.read()
        infile.close()
    file_size = len(plain_text)

    # Convert it to list of chars
    plain_text = list(plain_text)

    # Adjust plain_text size to make it a multiple of 16 as we need to process
    # 16 bytes (128-bits) at a time (AES has fixed block size of 128 bits
    # called state). To do so, find out how many bytes we need to append with
    # blank spaces.
    remainder_bytes = file_size % 16

    # Append blank spaces to the plain_text to make it multiple of 16
    for i in range(16 - remainder_bytes):
        plain_text.append(' ')

    # Adjusted length
    plain_text_len = len(plain_text)

    # Open cipher text file to write the encrypted plain text
    with open('%s_cipher.txt' % plain_text_file, 'w') as outfile:
        state_index = 0
        while state_index < plain_text_len:
            state_size = 16
            state = plain_text[state_index : state_index + state_size]
            encrypt_state(state, key_schedule, state_size)
            outfile.write(''.join(state))
            state_index = state_index + 16
            

    
if __name__ == '__main__':
    main(sys.argv[1:])
