import subprocess
import re
import os
from datetime import datetime

def run_volatility_command(command):
    """Run a Volatility command and return the output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def extract_keys_and_ivs(volatility_output):
    """Extract AES-256 keys and IVs along with their locations from Volatility cryptoscan output."""
    # AES-256 key: 64 hexadecimal characters (256 bits)
    keys = re.findall(r'(?i)AES key at 0x([0-9A-Fa-f]+) : ([0-9A-Fa-f]{64})', volatility_output)
    # IV for AES: 32 hexadecimal characters (128 bits)
    ivs = re.findall(r'(?i)IV at 0x([0-9A-Fa-f]+) : ([0-9A-Fa-f]{32})', volatility_output)
    return keys, ivs

def process_memory_dump(memory_dump_path):
    """Process a single memory dump to extract AES-256 keys and IVs along with their locations."""
    # Identify the memory profile
    imageinfo_command = f'volatility -f {memory_dump_path} imageinfo'
    imageinfo_output = run_volatility_command(imageinfo_command)
    
    # Extract suggested profile
    profile_match = re.search(r'Suggested Profile\(s\) : (.+?)\n', imageinfo_output)
    if not profile_match:
        print(f"Failed to identify memory profile for {memory_dump_path}.")
        return [], []
    profile = profile_match.group(1).split(',')[0]
    
    # Run cryptoscan
    cryptoscan_command = f'volatility -f {memory_dump_path} --profile={profile} cryptoscan'
    cryptoscan_output = run_volatility_command(cryptoscan_command)
    
    # Extract AES-256 keys and IVs along with their locations
    keys, ivs = extract_keys_and_ivs(cryptoscan_output)
    return keys, ivs

def main():
    # Directory containing memory dumps
    memory_dumps_dir = 'memory_dumps'
    
    # Get a list of memory dumps sorted by timestamp
    memory_dumps = sorted([f for f in os.listdir(memory_dumps_dir) if f.endswith('.raw')],
                          key=lambda x: datetime.strptime(x.split('.')[0], '%Y-%m-%d_%H-%M-%S'))
    
    # Aggregate keys and IVs from all memory dumps
    all_keys = []
    all_ivs = []
    
    for filename in memory_dumps:
        memory_dump_path = os.path.join(memory_dumps_dir, filename)
        print(f"Processing {memory_dump_path}...")
        keys, ivs = process_memory_dump(memory_dump_path)
        all_keys.extend([(filename, loc, key) for loc, key in keys])
        all_ivs.extend([(filename, loc, iv) for loc, iv in ivs])
    
    print("Aggregated AES-256 Keys:")
    for dump, loc, key in all_keys:
        print(f"Memory Dump: {dump}, Location: 0x{loc}, AES-256 Key: {key}")
    
    print("\nAggregated IVs:")
    for dump, loc, iv in all_ivs:
        print(f"Memory Dump: {dump}, Location: 0x{loc}, IV: {iv}")

if __name__ == "__main__":
    main()
