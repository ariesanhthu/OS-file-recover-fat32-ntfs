from offset_reader import read_offset_in_hex, read_offset_in_dec, read_offset_in_string, print_hex
import wmi

def list_disks():
    """Lists all physical drives available on the system."""
    disks = []
    for i in range(256):  # Assuming up to 256 disks could be connected
        try:
            disk_path = f"\\\\.\\PhysicalDrive{i}"
            if is_open(disk_path):
                disks.append(f"\\\\.\\PhysicalDrive{i}")
        except Exception:
            break  # Stop when no more drives are found
    return disks

# Return True if disk is available
def is_open(disk):
    """Check open disk."""
    try:
        if open(disk, "rb"):
            return True
    except Exception:
        return False
    
def listMBRDisk():
    disks = list_disks()
    offset = 0  # Example offset (1 sector after MBR)
    size = 512  # Number of bytes to read

    for disk in disks:
        print(disk)
        data = read_offset_in_hex(disk, offset, size)
        print_hex(data)
    
def partition_format(path, first_offset):  
    # Determine FAT32, NTFS or others

    if first_offset == 0: # Null partition
        return None
    
    if read_offset_in_string(path, first_offset + 0x52, 8).strip() == "FAT32":
        return "FAT32"
    elif read_offset_in_string(path, first_offset + 0x03, 4).strip() == "NTFS":
        return "NTFS"
    else:
        return None

# Function to get logical drive letter and its corresponding volume name from WMI based on physical drive number
def get_drive_info():
    c = wmi.WMI()
    partition_dict = {}

    # Query all disk drives and check for matching physical drive
    for disk in c.query("SELECT * FROM Win32_DiskDrive"):
        for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
            for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                try:
                    partition_dict[str(logical_disk.Caption)] = {
                        "letter": logical_disk.Caption, # C, D...
                        "volume_name": logical_disk.VolumeName,  # Volume name (Windows, Data, etc.)
                        "disk": disk.DeviceID,           # \\.\PhysicalDriveX
                        "partition": int(partition.Index), # Partition number
                        "first_offset": int(partition.StartingOffset),
                        "size": int(logical_disk.Size),
                    }
                except:
                    continue
                break
    return partition_dict

