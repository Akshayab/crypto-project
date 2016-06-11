import binascii
import os

# Author: Akshay Budhkar
# For purposes of understanding the algorithm - use the following terminology
# Message M, Response R, Encrypted Message Em, Encrypted Response Er
# Assume username for our purposes is abudhkar
# M = LOGIN abudhkar hello_world
# R = WELCOME abudhkar
# M = LOGIN abudhkar hellos_world
# R = PASSWORD MISMATCH
# We are only trying to find the users that were successful to login
# ASSUMPTION: If a user logs in twice, we show his name twice, list maintains order in which they logged in

# Final list
successful_users = []

# Size for every single message
MESSAGE_SIZE = 128

# Known words we are looking for
FIRST_KNOWN_WORD = binascii.hexlify(b'LOGIN ').ljust(256, b'0')
SECOND_KNOWN_WORD = binascii.hexlify(b'WELCOME ').ljust(256, b'0')
THIRD_KNOWN_WORD = binascii.hexlify(b'PASSWORD MISMATCH').ljust(256, b'0')
FOURTH_KNOWN_WORD = binascii.hexlify(b'INCORRECT USERNAME').ljust(256, b'0')

# Get both the log file messages
client_messages = open(os.path.expanduser('ClientLogEnc.dat'), 'rb')
server_messages = open(os.path.expanduser('ServerLogEnc.dat'), 'rb')

# This is what we will print at the end
final_message = ""

# Create the output file for users logged in
output_file = open(os.path.expanduser("Problem2.txt"), "w")


# Takes a hex value and converts to the corresponding ascii
# Thanks python for making this so hard
def hex_to_string_ascii(hex_val):
    return ''.join([chr(int(''.join(c), 16)) for c in zip(hex_val[0::2],hex_val[1::2])])


# Xors two hex values to return the resulting hex
def xor_of_hex(hex1, hex2):
    return '{:x}'.format((int(hex1, 16) ^ int(hex2, 16)))


# Xors two string values to get resulting string value
def xor_of_strings(string1, string2):
    return hex_to_string_ascii(xor_of_hex(binascii.hexlify(bytearray(str.encode(string1))), binascii.hexlify(bytearray(str.encode(string2)))))

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
        xor_with_third_known_word = xor_of_hex(hex_xor_of_encrypted_messages, THIRD_KNOWN_WORD)
        xor_with_fourth_known_word = xor_of_hex(hex_xor_of_encrypted_messages, FOURTH_KNOWN_WORD)

        # Should start with WELCOM or PASSWO depending on correct of wrong response
        response_start_words = hex_to_string_ascii(xor_with_first_known_word)
        message_start_words_successful = hex_to_string_ascii(xor_with_second_known_word)  # Should start with LOGIN ..
        message_start_words_unsuccessful = hex_to_string_ascii(xor_with_third_known_word) # Should start with LOGIN ..
        message_start_words_unsuccessful_username = hex_to_string_ascii(xor_with_fourth_known_word) # Should start with LOGIN ..

        if message_start_words_successful.startswith("LOGIN" ) and response_start_words.startswith("WELCOM"):
            # We made it half way! This is where we have one of the right combination of client-server conversation
            # The user has successfully logged in by this stage
            # Logic built on top of problem 1

            # This is used to tackle the remainder of the messages
            count = 6

            final_string = "" # Used to capture the username

            # These are the letters known in R. Will help us recover respective characters in M
            known_string = "E "
            password = ""
            user_ended = False

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
                # ljust according the other hex,
                #  so we get same sized hexes when we xor
                hex_known_strings = binascii.hexlify(bytearray(str.encode(known_string))).ljust(256 - count*2, b'0')

                xor_with_known_string = xor_of_hex(hex_xor_of_remaining_messages, hex_known_strings)

                remaining_message_start_words = hex_to_string_ascii(xor_with_known_string)

                # We reached the end of the username
                if remaining_message_start_words[0] == " " or user_ended:

                    if user_ended:
                        password += remaining_message_start_words[:2]
                    else:
                        password += remaining_message_start_words[1]

                    remaining_message_start_words = remaining_message_start_words[2:].strip().replace('\x00', '')
                    spaces = " " * len(remaining_message_start_words)

                    password += xor_of_strings(remaining_message_start_words, spaces)
                    break

                # Grab the first two characters from this string, those are decrypted characters
                known_string = remaining_message_start_words[:2]

                if remaining_message_start_words[1] == " ":
                    # Update the final string
                    final_string += remaining_message_start_words[0]
                    user_ended = True
                else:
                    # Update the final string
                    final_string += known_string

                # Increment the counter by 2, to grab the next two characters
                count += 2

            final_message += "[CORRECT] " + final_string + " " + password + "\n"
            successful_users.append(final_string)

        if message_start_words_unsuccessful.startswith("LOGIN") and response_start_words.startswith("PASSWO"):
            # We have reached half way here. This is second possible combination of client-server conversation
            # The user has attempted to log in with the wrong password

            # Grab the message/response after removing "LOGIN "
            cleaned_message = encrypted_client_message[6:]
            cleaned_response = encrypted_server_response[6:]

            hex_cleaned_message = binascii.hexlify(cleaned_message)
            hex_cleaned_response = binascii.hexlify(cleaned_response)

            hex_xor_of_cleaned_messages = xor_of_hex(hex_cleaned_message, hex_cleaned_response)

            # PASSWORD MISMATCH is followed by spaces, take that into account
            extra_spaces = " " * int(len(hex_xor_of_cleaned_messages.replace('00', ''))/2 - 11)
            known_string = "RD MISMATCH" + extra_spaces

            # ljust according to the other hex to avoid mismatch in hex sizes when xoring
            hex_known_strings = binascii.hexlify(bytearray(str.encode(known_string))).ljust(256 - 6*2, b'0')

            xor_with_known_string = xor_of_hex(hex_xor_of_cleaned_messages, hex_known_strings)
            final_string = hex_to_string_ascii(xor_with_known_string)

            # Format final string as needed
            final_message += "[WRONG]   " + final_string.replace('\x00', "") + "\n"

        if message_start_words_unsuccessful_username.startswith("LOGIN") and response_start_words.startswith("INCORR"):
            # We have reached half way here. This is second possible combination of client-server conversation
            # The user has attempted to log in with a wrong username

            # Grab the message/response after removing "LOGIN "
            cleaned_message = encrypted_client_message[6:]
            cleaned_response = encrypted_server_response[6:]

            hex_cleaned_message = binascii.hexlify(cleaned_message)
            hex_cleaned_response = binascii.hexlify(cleaned_response)

            hex_xor_of_cleaned_messages = xor_of_hex(hex_cleaned_message, hex_cleaned_response)

            # INCORRECT USERNAME is followed by spaces, take that into account
            extra_spaces = " " * int(len(hex_xor_of_cleaned_messages.replace('00', ''))/2 - 11)
            known_string = "ECT USERNAME" + extra_spaces

            # ljust according to the other hex to avoid mismatch in hex sizes when xoring
            hex_known_strings = binascii.hexlify(bytearray(str.encode(known_string))).ljust(256 - 6*2, b'0')

            xor_with_known_string = xor_of_hex(hex_xor_of_cleaned_messages, hex_known_strings)
            final_string = hex_to_string_ascii(xor_with_known_string)

            # Format final string as needed
            final_message += "[WRONG]   " + final_string.replace('\x00', "") + "\n"

    output_file.write(final_message)

finally:
    # Assumes both client and server messages have the same size
    client_messages.close()
    server_messages.close()

    # Don't let others manipulate this file
    output_file.close()