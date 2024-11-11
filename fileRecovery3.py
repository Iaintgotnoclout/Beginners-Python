import os  # Provides functions for interacting with the operating system
import sys  # Provides access to command-line arguments and other system-related functions
import hashlib  # Used for generating SHA-256 hash for recovered files

def get_sha256_hash_for_recovered_file(filename):
    """
    Calculates and returns the SHA-256 hash of a recovered file.

    :param filename: Name of the file to hash
    :return: SHA-256 hash as a hexadecimal string
    """
    hasher = hashlib.sha256()
    with open(filename, 'rb') as file:
        while True:
            chunk = file.read(1024)  # Read the file in 1024-byte chunks
            if not chunk:
                break
            hasher.update(chunk)  # Update the hash with the chunk of file data
    return hasher.hexdigest()  # Return the hash as a hex string

def get_file_by_start_offset(start_offset, files_found_dictionary):
    """
    Finds a file in the dictionary based on a given start offset.

    :param start_offset: The start offset to look for
    :param files_found_dictionary: Dictionary containing file start offsets
    :return: The filename if found, else None
    """
    for key in files_found_dictionary:
        if files_found_dictionary[key]['start'] == hex(start_offset):
            return key
    return None  # Return None if no matching file is found

if __name__ == '__main__':
    # Check if the disk image file path is provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python fileRecovery3.py <path_to_disk_image>")
        sys.exit(1)

    # Get the disk image file location from the command-line argument
    disk_image_location = sys.argv[1]

    # Check if the provided file path exists
    if not os.path.isfile(disk_image_location):
        print(f"Error: The file '{disk_image_location}' does not exist.")
        sys.exit(1)

    # Dictionary to store file signatures based on header and trailer byte patterns
    magic_bytes = {
        'JPG': {'header': b'\xFF\xD8\xFF\xE0', 'trailer': b'\xFF\xD9'},
        'GIF': {'header': b'\x47\x49\x46\x38', 'trailer': b'\x00\x3B'},
        'PDF': {'header': b'\x25\x50\x44\x46', 'trailer': b'\x0d\x0a\x25\x25\x45\x4F\x46\x0d\x0a'},
        'AVI': {'header': b'\x41\x56\x49\x20\x4c\x49\x53\x54', 'trailer': b'\x01\x00'},
        'PNG': {'header': bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), 'trailer': b'\x49\x45\x4E\x44\xAE\x42\x60\x82'}
    }

    # Dictionary to store information about files found in the disk image
    files_found = {}

    # Counter to assign unique names to recovered files
    files_found_count = 0

    # Open the disk image and read contents as bytes
    with open(disk_image_location, 'rb') as f:
        file_size = os.path.getsize(disk_image_location)  # Get the file size in bytes
        offset = 0  # Initialize offset to start reading from the beginning of the file

        # Get the length of the longest file signature header for reading chunks
        max_header_length = max(len(sig['header']) for sig in magic_bytes.values())

        # Loop through the file until the end
        while offset < file_size:
            f.seek(offset)  # Move to the current offset
            current_bytes = f.read(max_header_length)  # Read bytes equal to the max header length

            for file_type, signature in magic_bytes.items():
                header = signature['header']

                if header in current_bytes:
                    # Increment count and create a unique filename
                    files_found_count += 1
                    file_name = "File" + str(files_found_count) + "." + file_type.lower()

                    # Special handling for AVI files due to their unique structure
                    if file_type == 'AVI':
                        files_found[file_name] = {'start': hex(offset + current_bytes.index(header[0]) - 8)}
                        f.seek(offset - 4)
                        avi_size_bytes = f.read(4)  # Get AVI file size from 4-byte value
                        end_offset = offset + current_bytes.index(header[0]) - 8 + int.from_bytes(avi_size_bytes, byteorder='little') + 7
                        files_found[file_name].update({'end': hex(end_offset)})
                        offset = offset + current_bytes.index(header[0]) + len(header)
                        break
                    else:
                        # For non-AVI files, try to determine the end offset by looking for the next file header
                        next_file_offset = None
                        for next_offset in range(offset + len(current_bytes), file_size):
                            f.seek(next_offset)
                            next_bytes = f.read(max_header_length)
                            for next_file_type, next_signature in magic_bytes.items():
                                if next_signature['header'] in next_bytes:
                                    next_file_offset = next_offset
                                    break
                            if next_file_offset:
                                break
                        if next_file_offset:
                            end_offset = next_file_offset - 1
                        else:
                            end_offset = file_size  # If no next header found, assume file ends at the end of the disk image

                        # Store the start and end offsets in the dictionary
                        files_found[file_name] = {'start': hex(offset + current_bytes.index(header[0])), 'end': hex(end_offset)}
                        offset = end_offset + 1  # Move offset to the end of the current file
                        break
            else:
                # Increment offset if no header match found
                offset += 1

   # Reopen the disk image for carving out the files found
with open(disk_image_location, 'rb') as f:
    for key in files_found.keys():
        with open(key, 'wb') as recovered_file:
            # Ensure the 'end' key exists before accessing it
            start_offset = int(files_found[key]['start'], 16)
            end_offset = int(files_found[key]['end'], 16)

            recovered_file_size = end_offset - start_offset + 1
            f.seek(start_offset)
            bytes_to_write = f.read(recovered_file_size)
            recovered_file.write(bytes_to_write)

        # File has been written, now calculate SHA256
        file_hash = get_sha256_hash_for_recovered_file(key)
        files_found[key].update({'SHA256': file_hash})

# Output the number of files found and details of each file
print(f"The program found {files_found_count} files in the disk image.\n")
for key, value in files_found.items():
    print(f"{key}, Start Offset: {value['start']}, End Offset: {value.get('end', 'N/A')}")
    print(f"SHA-256: {value['SHA256']}")
    print()
