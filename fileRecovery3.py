import os  # Provides functions for interacting with the operating system (e.g., file and directory operations)
import sys  # Provides access to command-line arguments and other system-related functionality
import hashlib  # Used for generating SHA-256 hash for recovered files (used for file integrity verification)

# Function to compute SHA-256 hash for a file
def compute_sha256_for_file(filename):
    """
    Calculates and returns the SHA-256 hash of a recovered file.

    :param filename: Name of the file to hash
    :return: SHA-256 hash as a hexadecimal string
    """
    # Initialize SHA-256 hasher
    hasher = hashlib.sha256()

    # Open the file in binary read mode
    with open(filename, 'rb') as file:
        while True:
            # Read the file in 1024-byte chunks
            chunk = file.read(1024)
            if not chunk:
                break  # Exit the loop if the end of the file is reached
            hasher.update(chunk)  # Update the hash with the chunk of data

    # Return the hexadecimal representation of the hash
    return hasher.hexdigest()

# Function to find a file in the dictionary based on the given start offset
def find_file_by_offset(start_offset, recovered_files_dictionary):
    """
    Finds a file in the dictionary based on a given start offset.

    :param start_offset: The start offset to look for
    :param recovered_files_dictionary: Dictionary containing file start offsets
    :return: The filename if found, else None
    """
    for file_name_in_dict in recovered_files_dictionary:
        # Check if the current file's start offset matches the given offset
        if recovered_files_dictionary[file_name_in_dict]['start'] == hex(start_offset):
            return file_name_in_dict  # Return the filename if a match is found
    return None  # Return None if no matching file is found

# Main execution block
if __name__ == '__main__':
    # Check if the correct number of arguments (disk image path) is provided
    if len(sys.argv) != 2:
        print("Usage: python fileRecovery3.py <path_to_disk_image>")
        sys.exit(1)  # Exit with error if incorrect number of arguments is provided

    # Get the disk image file path from the command-line argument
    image_file_path = sys.argv[1]

    # Check if the provided file path exists and is a valid file
    if not os.path.isfile(image_file_path):
        print(f"Error: The file '{image_file_path}' does not exist.")
        sys.exit(1)  # Exit with error if the file does not exist

    # Create or recreate the RecoveredFiles directory
    recovered_dir = "./RecoveredFiles"
    if os.path.exists(recovered_dir):
        # Remove existing directory to start fresh
        for file in os.listdir(recovered_dir):
            os.remove(os.path.join(recovered_dir, file))
        os.rmdir(recovered_dir)
    os.mkdir(recovered_dir)

    # Dictionary to store file signatures based on header and trailer byte patterns for different file types
    file_signatures = {
        'JPG': {'header': b'\xFF\xD8\xFF\xE0', 'trailer': b'\xFF\xD9'},
        'GIF': {'header': b'\x47\x49\x46\x38', 'trailer': b'\x00\x3B'},
        'PDF': {'header': b'\x25\x50\x44\x46', 'trailer': b'\x0d\x0a\x25\x25\x45\x4F\x46\x0d\x0a'},
        'AVI': {'header': b'\x41\x56\x49\x20\x4c\x49\x53\x54', 'trailer': b'\x01\x00'},
        'PNG': {'header': bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), 'trailer': b'\x49\x45\x4E\x44\xAE\x42\x60\x82'}
    }

    # Dictionary to store information about files found in the disk image (start/end offsets)
    recovered_files = {}

    # Counter to assign unique names to recovered files
    recovered_files_count = 0

    # Open the disk image file and read it in binary mode
    with open(image_file_path, 'rb') as image_file:
        image_file_size = os.path.getsize(image_file_path)  # Get the size of the disk image file in bytes
        offset = 0  # Initialize offset to start reading from the beginning of the file

        # Get the length of the longest header pattern to determine the maximum chunk size for reading
        max_signature_length = max(len(sig['header']) for sig in file_signatures.values())

        # Loop through the file until the end
        while offset < image_file_size:
            image_file.seek(offset)  # Move the file pointer to the current offset
            read_bytes = image_file.read(max_signature_length)  # Read bytes equal to the max header length

            # Check each file type and its signature patterns
            for file_type, signature in file_signatures.items():
                header = signature['header']  # Extract the header signature for the file type

                if header in read_bytes:  # If the header pattern is found in the read bytes
                    # Increment recovered files count and generate a unique file name
                    recovered_files_count += 1
                    recovered_file_name = os.path.join(recovered_dir, "File" + str(recovered_files_count) + "." + file_type.lower())

                    # Calculate the start offset for the file where the header pattern was found
                    start_offset = offset + read_bytes.index(header)

                    # Find the trailer pattern for the file type
                    trailer = signature['trailer']
                    image_file.seek(start_offset)  # Seek to the start offset

                    # Initialize end_offset and begin searching for the trailer pattern
                    end_offset = start_offset
                    while end_offset < image_file_size:
                        chunk = image_file.read(1024)  # Read file in 1024-byte chunks
                        if trailer in chunk:  # If the trailer is found in the chunk
                            end_offset += chunk.index(trailer) + len(trailer) - 1  # Set end_offset after the trailer
                            break
                        end_offset += len(chunk)  # Increment end_offset by the chunk size if trailer not found

                    # Store the start and end offsets of the file in the dictionary
                    recovered_files[recovered_file_name] = {
                        'start': hex(start_offset),
                        'end': hex(end_offset)
                    }
                    offset = end_offset + 1  # Move the offset to the next potential file location
                    break
            else:
                # If no header match was found, increment offset by 1 and continue searching
                offset += 1

    # Reopen the disk image for carving out the files found during the search
    with open(image_file_path, 'rb') as image_file:
        # Iterate over each file found in the recovered files dictionary
        for file_name_in_dict in recovered_files.keys():
            with open(file_name_in_dict, 'wb') as recovered_file:
                # Ensure that the 'start' and 'end' values exist and convert them from hexadecimal to integer
                start_offset = int(recovered_files[file_name_in_dict]['start'], 16)
                end_offset = int(recovered_files[file_name_in_dict]['end'], 16)

                # Calculate the recovered file size and extract the appropriate bytes from the disk image
                recovered_file_size = end_offset - start_offset + 1
                image_file.seek(start_offset)  # Seek to the start offset of the file
                bytes_to_write = image_file.read(recovered_file_size)  # Read the file content
                recovered_file.write(bytes_to_write)  # Write the content to the new file

            # After writing the file, compute its SHA-256 hash for verification
            file_hash = compute_sha256_for_file(file_name_in_dict)
            recovered_files[file_name_in_dict].update({'SHA256': file_hash})  # Store the SHA-256 hash in the dictionary

    # Output the number of files found and the details for each recovered file
    print(f"The program found {recovered_files_count} files in the disk image.\n")
    for file_name_in_dict, file_info in recovered_files.items():
        print(f"{file_name_in_dict}, Start Offset: {file_info['start']}, End Offset: {file_info['end']}")
        print(f"SHA-256: {file_info['SHA256']}")  # Output the SHA-256 hash of the recovered file

    print(f"\nRecovered files are saved in '{recovered_dir}' directory.")
