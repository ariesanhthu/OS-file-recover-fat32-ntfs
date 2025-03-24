from offset_reader import read_offset_in_hex, read_offset_in_dec
from converter import byte_converter
from dos83_regulation import is_dos_8_3
import re

class FAT32:
    def __init__(self, disk, first_offset):
        self.begin = first_offset
        self.disk = disk
        self.mbs()

    def read_offset(self, offset, size):
        return read_offset_in_dec(self.disk, self.begin + offset, size)
    
    def mbs(self):
        self.sector_size = self.read_offset(0x0B, 2)                     # Sector size in bytes
        self.cluster_size = self.read_offset(0x0D, 1) * self.sector_size # Cluster size in bytes
        self.mbs_size = self.read_offset(0x0E, 2) * self.sector_size     # MBS size in bytes
        self.fat_num = self.read_offset(0x10, 1)                         # Number of fat tables
        self.volume_size = self.read_offset(0x20, 4) * self.sector_size  # Volume size in bytes
        self.fat_size = self.read_offset(0x24, 4) * self.sector_size     # Each Fat table size in bytes
        self.RDET_cluster_begin = self.read_offset(0x2C, 4)              # First RDET cluster to start counting (2 in general)

    def read_cluster(self, cluster_number):
        """Read data in a given cluster"""
        offset = self.begin + self.mbs_size + (self.fat_num * self.fat_size) + ((cluster_number - self.RDET_cluster_begin) * self.cluster_size)
        return read_offset_in_hex(self.disk, offset, self.cluster_size)
    
    def read_fat_chain(self, start_cluster):
        """Duyệt qua bảng FAT để lấy chuỗi cluster từ cluster bắt đầu."""
        chain = []
        current_cluster = start_cluster

        # Offset của bảng FAT
        fat_offset = self.begin + self.mbs_size

        while True:
            chain.append(current_cluster)
            fat_entry_offset = fat_offset + (current_cluster * 4)  # Mỗi entry dài 4 byte trong FAT32
            next_cluster = read_offset_in_dec(self.disk, fat_entry_offset, 4)

            # Kiểm tra cluster tiếp theo
            if next_cluster >= 0x0FFFFFF7:  # End of file (EOF)
                break
            elif next_cluster == 0x00000000:  # This cluster link is deleted
                break

            current_cluster = next_cluster  # Move to the next cluster
        return chain

    def clean_lfn_name(self, raw_name):
        raw_name = re.sub(b'(\x00\x00|\xFF\xFF)+$', b'', raw_name)
        return raw_name
    
    def scan_quick(self):
        """Find all deleted files from either RDET or SDET"""
        deleted_files = []
        visited = {}
    
        def read_directory(cluster_number, depth):
            """Đọc và duyệt qua một thư mục từ cluster chỉ định."""
            
            if depth > 1000 or cluster_number in visited: # Call too deep or this cluster is visited
                return
            
            visited[cluster_number] = True
            cluster_data = self.read_cluster(cluster_number)

            if cluster_data is None: # If no data returned then skip
                return
            
            entries = [cluster_data[i: i + 32] for i in range(0, len(cluster_data), 32)]  # Each entry has 32 bytes
            
            lfn_stack = []  # To temporarily save long name
            last_found_lfn = -1

            for index, entry in enumerate(entries):
                # If the entry is null, then skip
                if entry[0] == 0x00:  
                    continue
                
                if last_found_lfn + 1 != index: 
                    lfn_stack = []

                # Check Long file name (LFN)
                if entry[11] == 0x0F:
                    lfn_part = (
                        self.clean_lfn_name(entry[1:11] + entry[14:26] + entry[28:32])
                    ).decode("utf-16le", errors="ignore")
                    lfn_stack.insert(0, lfn_part)  # Ghép theo thứ tự ngược
                    last_found_lfn = index
                    continue
                
                # If it's volume label/system then skip
                mask = 0b00001100
                if mask & entry[0x0B]:
                    continue
                
                # Assign name from LFN or from main entry if the name is too short
                if lfn_stack:
                    full_name = "".join(lfn_stack).strip()
                else:
                    full_name = (entry[0:8]).decode("utf-8", errors="ignore").strip()
                    if not is_dos_8_3(full_name): continue
                    extension = (entry[8:11]).decode("utf-8", errors="ignore").strip()

                    if extension:
                        if not is_dos_8_3(extension): continue
                        full_name += "." + extension

                first_cluster = int.from_bytes(entry[26:28] + entry[20:22], "little")
                file_size = int.from_bytes(entry[28:32], "little")
                if entry[0] == 0xE5 and ((entry[11] & 0x20) or (entry[11] & 0x21)):  # Deleted file only
                    deleted_files.append({
                        "name": full_name,
                        "first_cluster": first_cluster,
                        "file_size": file_size,
                    })
                
                if (entry[11] & 0x10) or (entry[11] & 0x11):  # If entry is/was a directory
                    if full_name == "." or full_name == "..": # Don't try to visit current and parent directory
                        continue
                    subdir_cluster = int.from_bytes(entry[26:28] + entry[20:22], "little")
                    if subdir_cluster >= self.RDET_cluster_begin:  # Valid cluster
                        read_directory(subdir_cluster, depth + 1)

            cluster_chain = self.read_fat_chain(cluster_number) # Scan for all clusters belong to this RDET or SDET
            for cluster in cluster_chain:
                read_directory(cluster, depth + 1)
            

        # Start scanning from cluster "zero"
        read_directory(self.RDET_cluster_begin, 0)
        return deleted_files

    def recover_data(self, path_to_filename, file_info: dict):
        """Khôi phục dữ liệu từ một file bị xóa mà không dựa vào bảng FAT."""
        bytes_read = 0

        current_cluster = file_info["first_cluster"]
        try:
            with open(path_to_filename, "wb") as file:
                while bytes_read < file_info["file_size"]:
                    cluster_data = self.read_cluster(current_cluster)

                    if cluster_data is None: # If reading this cluster failed (maybe due to bad bits status)
                        raise Exception("No data returns")
                    
                    bytes_to_read = min(self.cluster_size, file_info["file_size"] - bytes_read)
                    file.write(cluster_data[:bytes_to_read])
                    bytes_read += bytes_to_read

                    # Nếu đọc hết cluster hiện tại mà chưa đạt kích thước file, thử đọc tiếp cluster kế tiếp
                    current_cluster += 1  # Chỉ đơn giản là đọc tiếp cluster tiếp theo liên tiếp
        except Exception as e:
            print(f"Error while recovering file: {e}")
            return

    def scan_all(self):
        """Scan all potential clusters to find valid or deleted SDET entries."""
        sdet_files = []
        total_clusters = self.volume_size // self.cluster_size  # Tổng số cluster trong volume

        for cluster_number in range(self.RDET_cluster_begin, total_clusters):
            try:
                lfn_stack = []  # To temporarily save long name
                last_found_lfn = -1
                cluster_data = self.read_cluster(cluster_number)

                if cluster_data is None: # If reading this cluster failed (maybe due to bad bits status)
                        raise Exception("No data returns")
                
                entries = [cluster_data[i:i + 32] for i in range(0, len(cluster_data), 32)]  # Mỗi entry dài 32 byte
                
                for index, entry in enumerate(entries):
                    # Kiểm tra entry bị xóa
                    if entry[0] != 0xE5:
                        continue
                    
                    # If LFN chain does not continuous, then reset this list
                    if last_found_lfn + 1 != index: 
                        lfn_stack = []

                    # Check Long file name (LFN)
                    if entry[11] == 0x0F:
                        lfn_part = (
                            self.clean_lfn_name(entry[1:11] + entry[14:26] + entry[28:32])
                        ).decode("utf-16le", errors="ignore")
                        lfn_stack.insert(0, lfn_part)  # Ghép theo thứ tự ngược
                        last_found_lfn = index
                        continue

                    # Kiểm tra byte thuộc tính (entry[11])
                    attributes = entry[11]
                    valid_attributes = {0x10, 0x20, 0x11, 0x21}  # Các giá trị hợp lệ
                    if attributes not in valid_attributes:
                        continue

                    # Khôi phục hoặc đọc tên file
                    name_bytes = entry[1:8]  # Khôi phục ký tự đầu tiên
                    
                    full_name = (name_bytes).decode("utf-8", errors="ignore").strip()
                    extension = (entry[8:11]).decode("utf-8", errors="ignore").strip()          
                    if extension:
                        full_name += "." + extension        

                    # If we have 
                    if lfn_stack:
                        full_name = "".join(lfn_stack).strip()

                    first_cluster = int.from_bytes(entry[26:28] + entry[20:22], "little")
                    file_size = int.from_bytes(entry[28:32], "little")

                    if  first_cluster < self.RDET_cluster_begin or first_cluster > total_clusters or\
                        file_size < 0 or file_size > self.volume_size:
                        continue
                    
                    print(f"Scanning: Filename: {full_name}, size: {byte_converter(file_size)}")
                    sdet_files.append({
                        "name": full_name,
                        "first_cluster": first_cluster,
                        "file_size": file_size,
                    })

            except Exception:
                continue

        return sdet_files
