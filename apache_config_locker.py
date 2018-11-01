#!/usr/bin/env python
# Apache Config Locker

# Description--
# This script will stop apache if it is already started, decrypt the config file
# and then restart apache and finally re-encrypt the config file.  The purpose is
# to allow a server to maintain important passwords and API keys out of cleartext.
# The Apache config file should therefore load a list of passwords into environment.

## Import Modules ##
import os
import sys
import logging
import time
import hashlib
from Crypto.Cipher import AES
import smtplib
from subprocess import run

## Import data from file_list
def decrypt_config(key, enncrypted_path_and_filename, config_path_and_filename):

	try:

		# Collect the checksum map stored in file to variable called original_filepath_array
		with open(encrypted_path_and_filename) as encrypted_config_file:
			encrypted_config_content = encrypted_config_file.read()

		# Decrypt the file from encrypted format
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		decryptor = AES.new(key, mode, IV=IV)
		encrypted_config_content = decryptor.decrypt(encrypted_config_content)

		# Check that the first line is the password correct confirmation
		# If the password confirmation is not correct, then return false
		if original_file_content[0] != "#":
			print "Incorrect Password!"
			return False

		# You may also want to remove whitespace characters like `\n` at the end of each line
		for item in original_file_content:

			# Strip whitespace and newlines
			item = item.strip()

			# Check for the character used to pad the encryption
			if item.endswith("@"):
				pass
			# If line from file is folder
			elif item.endswith('/'):
				original_filepath_array[0].append(item)
			# If line from file is file
			else:
				# Strip whitespace from line
				item = item.strip()
				# Split the line value by comma
				line_list = item.split(",")
				# append the filename and checksum into array
				original_filepath_array[1].append(line_list[0].strip())
				original_filepath_array[2].append(line_list[1].strip())
		# Return the array
		return True

## Parses the command argument sys.arg into command set, also encrypt password for use
def build_command_arguments(argument_array, allowed_args_array):

	## Include logger in the main function
	logger = logging.getLogger("MD5_checksum_validator")

	try:
		# Create an array to store modified command line arguemnts
		command_arg = {}

		# Check that the argument array is proper length (4)
		if len(argument_array) != 4:
			return False
		# Pop off the first element of array because it's the application filename
		argument_array.pop(0)

		# find the password argument and take the password part and encrypt, attach as the second argument
		if "-p" in argument_array:
			# Calculate position of -p argument
			password_flag_position = argument_array.index("-p")
			# Pop the flag off the array
			argument_array.pop(password_flag_position)
			# Look for the password in the next position
			raw_password = argument_array[password_flag_position]
			# Pop the password string out of the argument array
			argument_array.pop(password_flag_position)
			# encrypt the raw_password into the form used for encryption
			key = hashlib.sha256(raw_password).digest()
			# Append the key back onto the end of the command line arguement array
			command_arg.update({"key" : key})

		# If there is no password argument, then the command line is failed
		else:
			return False

		# For loop to modify elements and strip "-"
		for item in argument_array:
			if item in allowed_args_array:
				item = item.replace('-', '')
				command_arg.update({"command" : item})

		# The final array should always be list of length 2
		if len(command_arg) != 2:
			return False
		# Return the modified array of length is proper
		else:
			return command_arg
	except Exception as e:
		# Collect the exception information
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		# Print the error
		print 'Failed to build command arguments: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		# Log error with creating filepath
		logger.error('Failed to build command arguments: ' + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

# Iteration of bytes of each file
def hash_bytestr_iter(bytesiter, hasher, ashexstr=False):
    for block in bytesiter:
        hasher.update(block)
    return (hasher.hexdigest() if ashexstr else hasher.digest())


def file_as_blockiter(afile, blocksize=65536):
    with afile:
        block = afile.read(blocksize)
        while len(block) > 0:
            yield block
            block = afile.read(blocksize)

# Encrypt the configuration file
def encrypt_config(key, config_path_and_filename, encrypted_path_and_filename):

	# Use the config_path_and_filename to find the file and store in enncrypted_path_and_filename
	try:

		# Open the decrypted config file and encrypt
		config_file = open(config_path_and_filename, "r")
		config_file_array = config_file.readlines()

		# Write data to file
		encrypted_data_file_output = open(encrypted_path_and_filename, "w+")
		# Create a string to write to file
		data_string = ""
		for item in config_file_array:
			data_string += item + "\n"

		# Encode data string to utf-8 to make sure it's common encoding
		data_string = data_string.encode('utf-8')

		# Encrypt the data string to be written to file with padding
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		encryptor = AES.new(key, mode, IV=IV)
		config_file_data_in_ciphertext = encryptor.encrypt(data_string + ((16 - len(data_string)%16) * "@"))

		# Write the encrypted data to file
		encrypted_data_file_output.write(data_in_ciphertext)
		# Close the file
		encrypted_data_file.close();

	except Exception as e:
		# Collect the exception information
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		# Print the error
		print 'Error writing encrypted config to file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		# Log error with creating checksum map
		logger.error('Error writing encrypted config to file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False

# Remove the config file
def remove_config(key, config_path_and_filename, encrypted_path_and_filename):

	try:

		# Check that the encrypted version of the file exists already, can be decryted successfully
		# using the provided password before deleting the original file.
		# TODO:

		# Delete the file config_path_and_filename
		os.remove(config_path_and_filename)
		# Print the success to stdout
		print 'Unencrypted config file removed.'
		# Log success removing config file
		logger.error('Unencrypted config file removed.')

	except Exception as e:
		# Collect the exception information
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		# Print the error
		print 'Error removing unencrypted config file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno)
		# Log error with creating checksum map
		logger.error('Error removing unencrypted config file: ' + str(e) + str(e) + str(exc_type) + str(fname) + str(exc_tb.tb_lineno))
		return False


# Confirm encrypted config file exists and can be decrypted using key
def confirm_config(key, encrypted_path_and_filename):
	try:

		# Collect the checksum map stored in file to variable called original_filepath_array
		with open(encrypted_path_and_filename) as encrypted_config_file:
			encrypted_config_content = encrypted_config_file.read()

		# Decrypt the file from encrypted format
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		decryptor = AES.new(key, mode, IV=IV)
		encrypted_config_content = decryptor.decrypt(encrypted_config_content)

		# Check that the first line is the password correct confirmation
		# If the password confirmation is not correct, then return false
		if original_file_content[0] == "#":
			print "Encrypted File Confirmed!"
			return True


# Build the output for command line instructions
def build_argument_output():
	argument_output = "Usage : apache_config_locker.py [-p <password>] [-map | -validate]\n"
	argument_output += "-h, -help : print help menu\n"
    argument_output += "-start : initialize by loading apache with config file and then encrypting it\n"
    argument_output += "-open : decrypt the config file for editing\n"
	argument_output += "-reload : stop apache, restart using decrypted file, and then re-encrypt the config file\n"
	argument_output += "-p <password> : enter the password required to decrypt the data payload\n"
	return argument_output

# Setup logging
def setup_logger(log_file):
    logger = logging.getLogger('Apache_config_locker')
    log_handler = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)

## Main Function Starts Here ##
if __name__ == '__main__':

	# Application Name used in report
	application_name = "Test Application"
	## Declare required variables for filepath and config filename
	apache_config_base_directory_path = "/Users/development/Documents/Software/scripts/python/checksum_validator/test_suite"
	config_filename = "config_test.conf"
	log_filename = "/Users/development/Documents/Software/scripts/python/apache_config_locker/log"
    encrypted_config_path = "/Users/development/Documents/Software/scripts/python/checksum_validator/test_suite"
    encrypted_config_filename = "enc_locker"
	allowed_args_array = ["-reload", "-start", "-open", "-p" "-h", "-help"]

    # Build the complete paths and filenames
    config_path_and_filename = apache_config_base_directory_path + config_file
    encrypted_path_and_filename = encrypted_config_path + encrypted_config_filename

	## Run function to setup logger
	setup_logger(log_file)
	## Include logger in the main function
	logger = logging.getLogger("Apache_config_locker")

	## Perform analysis of command line args into another array
	command_arg = build_command_arguments(sys.argv, allowed_args_array)

	## Check return from command line arg bulder and if no command line args
	## print error message and menu
	if command_arg == False or command_arg["command"] == "h" or command_arg["command"] == "help":
		print "command argument error...."
		## Print out full argument help menu
		print build_argument_output()

	## Load Apache, then encrypt the config file and delete it
    elif command_arg["command"] == 'start':

        # Start apache using the config file
        return_code = run(["service", "apache2", "start"])

        # Encrypt the config file
        return_success = encrypt_config(comand_arg["key"], config_path_and_filename, encrypted_path_and_filename)
        # Delete the unencrypted config file
        return_success = remove_config(config_path_and_filename)

    ## Decrypt the config file for editing
	elif command_arg["command"] == 'open':

        # decrypt the config file and place into appropriate directory
        return_success = decrypt_config(comand_arg["key"], config_path_and_filename, encrypted_path_and_filename)

    ## Pass the filepath_array to create_checksum_map
    elif command_arg["command"] == 'reload':

		# Decrypt the config file and place into appropriate directory
        return_success = decrypt_config(comand_arg["key"], config_path_and_filename, encrypted_path_and_filename)

		# Reload Apache
        return_code = run(["service", "apache2", "reload"])

		# Encrypt the config file
        return_success = encrypt_config(comand_arg["key"], config_path_and_filename, encrypted_path_and_filename)
