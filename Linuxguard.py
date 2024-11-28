import os
import hashlib

# Sample virus signature database (a dictionary with file signatures)
# In real-world usage, this should be populated with actual malware hashes (MD5, SHA256)
virus_db = {
    "d41d8cd98f00b204e9800998ecf8427e": "EICAR Test Virus",  # MD5 hash of EICAR test file
    "5baa61e4c9b93f3f0682250b6cf8331b": "Basic Malware Example"  # SHA1 hash of a sample file
}

def get_file_hash(file_path, hash_algo='md5'):
    """Generate the hash of the file"""
    hash_func = hashlib.new(hash_algo)
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def scan_directory(directory_path):
    """Scan all files in a given directory"""
    infected_files = []
    print(f"Scanning directory: {directory_path}")
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Scanning {file_path}...")
            file_hash = get_file_hash(file_path)
            if file_hash in virus_db:
                infected_files.append((file_path, virus_db[file_hash]))
    return infected_files

def main():
    print("=== LinuxGuard: Linux Antivirus ===")
    directory = input("Enter the directory to scan (e.g., /home/user): ")
    
    infected_files = scan_directory(directory)
    
    if infected_files:
        print("\nInfected Files Found:")
        for file_path, malware in infected_files:
            print(f"[ALERT] {file_path} - {malware}")
    else:
        print("\nNo infections detected.")

if __name__ == "__main__":
    main()
