import mbr
from fat32 import FAT32
# from ntfs import NTFS
from offset_reader import read_offset_in_hex, read_offset_in_dec, read_offset_in_string, print_hex
from converter import byte_converter
import datetime
import subprocess

def partition_selection():
    # Ask user to input a valid drive letter
    while True:
        # List to hold all valid partitions
        supported_partitions = {}

        # Retrieve partition info for the given disk
        drive_info = mbr.get_drive_info()
        
        # If there are partitions, add them to the list
        for letter, info in drive_info.items():
            format_type = mbr.partition_format(info['disk'], info['first_offset'])

            if format_type is None:
                continue

            info['format'] = format_type

            if letter not in supported_partitions:
                supported_partitions[letter] = info

        # Print the available partitions with letter drives and volume names
        print("NTFS or FAT32 partitions found:\n")
        for letter, info in supported_partitions.items():
            print(f"Drive {letter},  volume_name: ({info['volume_name'] if len(info['volume_name']) else "NO NAME"}), disk: {info['disk']}, partition: {info['partition']}, format: {info['format']}")   

        print("\nType the letter with a colon (C:, D:, ...) to continue.") # Have to type exactly "C:" for instance
        print("Type BACK to exit.")
        print("Command: ", end="")
        choice = input().strip().upper()  # Get the user's input and convert it to uppercase

        if choice == "":
            continue

        if choice == "BACK": # Terminate
            print("Exit program")
            exit(0)

        # Check if the input is a valid drive letter
        selected_partition = None
        for letter in supported_partitions.keys():
            if letter == choice:
                selected_partition = supported_partitions[letter]
                break
        
        if selected_partition:
            print(f"You have selected drive {selected_partition['letter']} ({selected_partition['volume_name'] if selected_partition['volume_name'] else "NO NAME"})")
            print(f"Physical Drive: {selected_partition['disk']}")
            print(f"Partition: {selected_partition['partition']}")
            return selected_partition  # Exit the loop if the selection is valid
        else:
            print("Invalid selection. Please choose a valid drive letter (C:, D:, ...).")

def deleted_files(instance, mode = "quick"):
    print("Loading deleted files...")
    del_items = instance.scan_quick() if mode == "quick" else instance.scan_all()
    print("------------------------------------------------")
    print("Found:\n")

    for index, item in enumerate(del_items):
        print(f"Index {index}: Filename: {item["name"]}, size: {byte_converter(item["file_size"])}")

    print("\nNote: Due to data structure, some filename prefixes might be lost a few characters")
    return del_items

def partition_process():
    print("------------------------------------------------")
    disk = partition_selection()
    #print_hex(read_offset_in_hex(disk['disk'], disk['first_offset'], 512)) # Print master boot sector

    if disk['format'] == "FAT32":
        instance = FAT32(disk = disk['disk'], first_offset = disk['first_offset'])

       
 
        #del_items = deleted_files(instance) # Scan RDET first by defaultelif format == "NTFS":
        while True:
            print("------------------------------------------------")
            print("Choose any files to recover by typing their file indexes (eg. 4 17)")
            print("Type QUICK to scan quickly.")
            print("Type FULL to scan deeply.")
            print("Type BACK to return to partition choices.")
            print("Command: ", end="")
            choice = input().strip().upper()  # Get the user's input and convert it to uppercase

            if choice == "":
                continue

            if choice == "BACK":
                return partition_process()
            
            if choice == "QUICK":
                del_items = deleted_files(instance)
                continue
            
            if choice == "FULL":
                del_items = deleted_files(instance, "full")
                continue

            file_index_str = choice.split()
            file_index = []

            # Check conditions
            try:
                for index in file_index_str:
                    value = int(index)
                    file_index.append(value)
                    if 0 <= value < len(del_items):
                        continue
                    else:
                        1 / 0 # Raise any errors to exit  
                    
            except:
                print("Invalid selection. Please make sure all selections are valid and within allowed range.")
                continue

            print("Note: We recommend not to choose the recovery partition to prevent data loss.")
            print("Destination (where you want to save, eg. C:\\Program Files): ", end="")
            dest = input().strip().upper()  # Get the user's input and convert it to uppercase

            try:
                complete = 0
                print("Recovering...\nCompleted 0%")
                for index, item in enumerate(del_items):
                    if index in file_index:
                        current_datetime = datetime.datetime.now()
                        formatted_datetime = current_datetime.strftime("%d-%m-%Y_%H-%M-%S")
                        print(f"\nCreating {dest}\\{formatted_datetime}_{item["name"]} | recover from {item["name"]}, index #{index}")

                        instance.recover_data(f"{dest}\\{formatted_datetime}_{item["name"]}", item)

                        complete += 1
                        print(f"Completed {complete / len(file_index) * 100:.1f}%")
            except Exception as e:
                print("Something went wrong... Please try again")
                print(f"Error: {e}")
            print("\nDone\nComing back...")


    else:
        print("------------------------------------------------")
        print("Type CONTINUE to delete.")
        print("Type BACK to return to partition choices.")
        print("Command: ", end="")
        choice = input().strip().upper()  # Get the user's input and convert it to uppercase

        if choice == "BACK":
            return partition_process()
        
        if choice == "" or choice == "CONTINUE":
            # cmd = ['python', 'ntfsrecover.py', f"\\\\.\\{disk['letter']}"]

            # subprocess.run(cmd, check=True)

            # pattern = input("Recover files (Eg. *.jpg): ")
            # outdir = input(r"Destination (where you want to save, eg. C:\Program Files): ").rstrip('"')

            # cmd = ['python', 'ntfs.py', f"\\\\.\\{disk['letter']}", '--pattern', pattern, '--outdir', outdir]
            cmd = ['python', 'ntfs.py', disk['letter']]
            subprocess.run(cmd, check=True)
            # return
