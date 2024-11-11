import binascii, hashlib, re, sys
import os, os.path

# Supported file types and their signatures
FILE_SIGNATURES = {
    'MPG': {'header': '000001B', 'footer': '000001B7'},
    'PDF': {'header': '25504446', 'footer': '(0A2525454F46|0A2525454F460A|0D0A2525454F460D0A|0D2525454F460D)'},
    'BMP': {'header': '424D', 'footer': None},
    'GIF': {'header': '474946383761', 'footer': '003B'},
    'GIF': {'header': '474946383961', 'footer': '003B'},
    'JPEG': {'header': 'FFD8FF', 'footer': 'FFD9'},
    'DOCX': {'header': '504B030414000600', 'footer': '504B0506([A-F0-9]{36})'},
    'PNG': {'header': '89504E470D0A1A0A', 'footer': '49454E44AE426082'},
    'ZIP': {'header': '504B0304', 'footer': '504B17([A-F0-9]{34})000000'},
    'AVI': {'header': '52494646', 'footer': '61766168'}  # AVI signature
}

# Ensure disk file input is provided
if len(sys.argv) < 2:
    print("Usage: python fileRecovery.py <disk image>")
    sys.exit(1)

# Load disk image into memory as a hex string
try:
    with open(sys.argv[1], 'rb') as diskFile:
        raw_bytes = binascii.hexlify(diskFile.read()).upper().decode()
except Exception as e:
    print(f"Error reading disk image: {e}")
    sys.exit(1)

print("Size of disk: {:.2f} MB".format(len(raw_bytes) / (2 * 1024 * 1024)))

# Directory for recovered files
output_dir = "RecoveredFiles"
os.makedirs(output_dir, exist_ok=True)

# File recovery loop
allFiles = []
currentFile = None
sector_size = 1024 * 2  # 512 bytes * 2 for hex string size

# File recovery loop
for sector in range(0, len(raw_bytes), sector_size):
    current_sector_info = raw_bytes[sector:sector + sector_size]
    if sector % (2 * 1024 * 1024) == 0:
        print(f"Checking {(sector / (2 * 1024 * 1024)):.2f} MB")

    if currentFile:
        # Check for footer if inside a file
        footer_re = re.compile(FILE_SIGNATURES[currentFile['type']]['footer'])
        footer_match = footer_re.search(current_sector_info) if footer_re else None
        
        # If footer is found or if the file type is AVI and we don't care about a footer, complete the file
        if footer_match or (currentFile['type'] == 'AVI' and footer_match is None):
            currentFile['endOffset'] = sector + footer_match.end() if footer_match else sector + len(current_sector_info) // 2
            currentFile['full'] = True
            allFiles.append(currentFile)
            print(f"{currentFile['type']} file recovered!")
            currentFile = None
        else:
            # For all other files, continue adding data
            currentFile['fileLength'] += len(current_sector_info) // 2  # count bytes
            if currentFile['type'] != 'AVI' and currentFile['fileLength'] > 2097152:  # max 2 MiB for BMP as an example
                print(f"Max file size reached for {currentFile['type']}, aborting.")
                allFiles.append(currentFile)
                currentFile = None

    else:
        # Check for headers if not inside a file
        for file_type, sig in FILE_SIGNATURES.items():
            if re.match(sig['header'], current_sector_info):
                print(f"{file_type} file found!")
                currentFile = {
                    'type': file_type,
                    'startOffset': sector,
                    'endOffset': None,
                    'fileLength': 0,
                    'full': False
                }
                break

# Writing recovered files to disk and hashing
for i, file in enumerate(allFiles, start=1):
    if not file['full'] or file['startOffset'] is None or file['endOffset'] is None:
        continue
    output_path = os.path.join(output_dir, f"File{i}.{file['type'].lower()}")
    start = file['startOffset']
    end = file['endOffset']
    file_bytes = bytes.fromhex(raw_bytes[start*2:end*2])
    with open(output_path, 'wb') as f_out:
        f_out.write(file_bytes)
    file_hash = hashlib.sha256(file_bytes).hexdigest().upper()

    # Print output in the desired format
    print(f"File{i}.{file['type'].lower()}, Start Offset: {hex(start)}, End Offset: {hex(end)}")
    print(f"SHA-256: {file_hash}\n")

# Final output after processing all files
print(f"\nThe disk image contains {len(allFiles)} file{'s' if len(allFiles) > 1 else ''}.\n")
print("Recovered files are located in 'RecoveredFiles' folder.")
