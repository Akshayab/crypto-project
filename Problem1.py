import binascii
import os

# Author: Akshay Budhkar
# For purposes of understanding the algorithm - use the following terminology
# Message M, Response R, Encrypted Message Em, Encrypted Response Er
# Assume username for our purposes is abudhkar
# M = LOGIN abudhkar hello_world
# R = WELCOME abudhkar
# We are only trying to find the users that were successful to login
# ASSUMPTION: If a user logs in twice, we show his name twice, list maintains order in which they logged in

# Final list
successful_users = []

# Size for every single message
MESSAGE_SIZE = 128

# Known words we are looking for
FIRST_KNOWN_WORD = binascii.hexlify(b'WELCOME ').ljust(256, b'0')
SECOND_KNOWN_WORD = binascii.hexlify(b'LOGIN ').ljust(256, b'0')

# Get both the log file messages
client_file_name = 'ClientLogEnc.dat'
server_file_name = 'ServerLogEnc.dat'
if '_MEIPASS2' in os.environ:
    client_file_name = os.path.join(os.environ['_MEIPASS2'], client_file_name)
    server_file_name = os.path.join(os.environ['_MEIPASS2'], server_file_name)

client_messages = open(client_file_name, 'rb')
server_messages = open(server_file_name, 'rb')

# Create the output file for users logged in
output_file = open("Problem1.txt", "w")


# Takes a hex value and converts to the corresponding ascii
# Thanks python for making this so hard
def hex_to_string_ascii(hex_val):
    return ''.join([chr(int(''.join(c), 16)) for c in zip(hex_val[0::2],hex_val[1::2])])


# Xors two hex values to return the resulting hex
def xor_of_hex(hex1, hex2):
    return '{:x}'.format((int(hex1, 16) ^ int(hex2, 16)))

try:
    while True:
        # Grab one message each
        encrypted_client_message = client_messages.read(MESSAGE_SIZE)
        encrypted_server_response = server_messages.read(MESSAGE_SIZE)

        # Ensure we haven't reached the end
        if not (encrypted_client_message or encrypted_server_response):
            break

        hex_encrypted_server_response = binascii.hexlify(encrypted_server_response) # Er
        hex_encrypted_client_message = binascii.hexlify(encrypted_client_message) # Em

        # Er ^ Em = R ^ M
        hex_xor_of_encrypted_messages = xor_of_hex(hex_encrypted_client_message, hex_encrypted_server_response)

        xor_with_first_known_word =  xor_of_hex(hex_xor_of_encrypted_messages, FIRST_KNOWN_WORD)
        xor_with_second_known_word = xor_of_hex(hex_xor_of_encrypted_messages, SECOND_KNOWN_WORD)

        message_start_words = hex_to_string_ascii(xor_with_first_known_word)  # Should start with LOGIN ab
        response_start_words = hex_to_string_ascii(xor_with_second_known_word)  # Should start with WELCOM

        if message_start_words.startswith("LOGIN" ) and response_start_words.startswith("WELCOM"):
            # We made it half way! This is where we have the right combination of client-server conversation

            # This is used to tackle the remainder of the messages
            count = 6

            final_string = "" # Used to capture the username

            # These are the letters known in R. Will help us recover respective characters in M
            known_string = "E "

            while True:

                # If we reached the ends of M and R
                if count >= 128:
                    break

                # Substring message and response
                remaining_message = encrypted_client_message[count:]
                remaining_response = encrypted_server_response[count:]

                hex_remaining_message = binascii.hexlify(remaining_message)
                hex_remaining_response = binascii.hexlify(remaining_response)

                # R[count:] ^ M[count:]
                hex_xor_of_remaining_messages = xor_of_hex(hex_remaining_message, hex_remaining_response)

                # Convert known strings into hex, so we can XOR them
                # NOTE: This might be excessive
                # ljust according the other hex, so we get same sized hexes when we xor
                hex_known_strings = binascii.hexlify(bytearray(str.encode(known_string))).ljust(256 - count*2, b'0')

                xor_with_known_string = xor_of_hex(hex_xor_of_remaining_messages, hex_known_strings)

                remaining_message_start_words = hex_to_string_ascii(xor_with_known_string)

                # Grab the first two characters from this string, those are decrypted characters
                known_string = remaining_message_start_words[:2]

                # We reached the end of the username
                if known_string[0] == " ":
                    break

                if known_string[1] == " ":
                    final_string += known_string[0]
                    break

                # Update the final string
                final_string += known_string

                # Increment the counter by 2, to grab the next two characters
                count += 2

            successful_users.append(final_string)

    final_text = "\n".join(successful_users)
    output_file.write(final_text)

finally:
    # Assumes both client and server messages have the same size
    client_messages.close()
    server_messages.close()

    # Don't let others manipulate this file
    output_file.close()

