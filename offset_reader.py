def read_offset_in_hex(disk_path, *args):
    """Read from a given offset and its length. Params: disk path, offset1, size1, offset2, size2, ..."""
    try:
        with open(disk_path, "rb") as disk:
            disk.seek(0)
            data = b""  # Init data by empty 
            for idx in range(len(args) // 2):
                offset = args[idx * 2]  # Get offset
                size = args[idx * 2 + 1]  # Get size
                print(f"Reading offset: {offset}")
                disk.seek(offset // 512 * 512) 
                sectors = disk.read(offset % 512 + size)
                data += sectors[offset % 512 : offset % 512 + size]  # Get needed data & concatenate

            return data
        return None
    except:
        return None

def read_offset_in_dec(disk_path, *args):
    """Read from a given offset and its length. Params: disk path, offset1, size1, offset2, size2, ..."""
    data = read_offset_in_hex(disk_path, *args)
    if data != None:
        return int.from_bytes(data, byteorder='little') # Chuyển đổi dữ liệu bytes thành số nguyên
    return None

def read_offset_in_string(disk_path, *args):
    """Read from a given offset and its length. Params: disk path, offset1, size1, offset2, size2, ..."""
    data = read_offset_in_hex(disk_path, *args) 
    
    if data is None:
        return None  # No data to read
    
    result = ""
    for byte in data:
        if 32 <= byte <= 126: # If this is a valid character (0 <= byte <= 127), print as ASCII
            result += chr(byte) 
        else:
            result += '.'  # If not a valid character, replace by a dot

    return result

def print_hex(data):
    """Prints data in a hex dump format."""
    if data:
        for i in range(0, len(data), 16):
            hex_bytes = ' '.join(f"{byte:02x}" for byte in data[i:i+16])

            print(f"{i:09x}  {hex_bytes}")