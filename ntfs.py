from offset_reader import read_offset_in_hex, read_offset_in_dec, read_offset_in_string, print_hex
from converter import byte_converter

class NTFS:
    def __init__(self, disk, first_offset):
        self.begin = first_offset
        self.disk = disk
        self.sector_size = self.read_offset(0x0B, 2) # Sector size in bytes
        self.cluster_size = self.get_cluster_size()  # Cluster size in bytes
        self.mft_start = self.get_mft_start()        # MFT starting offset

#     def read_offset(self, offset, size):
#         return read_offset_in_dec(self.disk, self.begin + offset, size)

#     def get_cluster_size(self):
#         # Read cluster size from boot sector
#         sectors_per_cluster = self.read_offset(0x0D, 1)
#         return sectors_per_cluster * self.sector_size

#     def get_mft_start(self):
#         # Read MFT start position 
#         mft_start_cluster = self.read_offset(0x30, 8)
#         return self.begin + mft_start_cluster * self.cluster_size

#     def read_mft_entry(self, entry_number):
#         """Read a MFT entry"""
#         offset = self.mft_start + (entry_number * 1024)  # Commonly an entry size = 1024
#         return read_offset_in_hex(self.disk, offset, 1024)

#     # def scan_quick(self):
#     #     """Liệt kê tất cả các file đã bị xóa kèm kích thước và địa chỉ offset"""
#     #     deleted_files = []
#     #     entry_number = 0  # Bắt đầu từ entry đầu tiên trong MFT

#     #     while True:
#     #         try:
#     #             # Đọc một entry trong MFT
#     #             mft_entry = self.read_mft_entry(entry_number)

#     #             # Kiểm tra xem entry có hợp lệ không (chữ ký 'FILE')
#     #             if mft_entry[:4] != b"FILE":
#     #                 entry_number += 1
#     #                 continue

#     #             # Kiểm tra cờ trạng thái (đã xóa hay không)
#     #             flags = int.from_bytes(mft_entry[0x16:0x18], "little")
#     #             if flags != 0x00:  # Không phải entry đã xóa
#     #                 entry_number += 1
#     #                 continue

#     #             # Địa chỉ offset đầu tiên của entry này
#     #             offset_entry = self.mft_start + entry_number * 1024

#     #             # Lấy danh sách các attribute trong entry
#     #             offset = int.from_bytes(mft_entry[0x14:0x16], "little")
#     #             filename = None
#     #             file_size = None

#     #             while offset < len(mft_entry):
#     #                 # Đọc loại attribute và kích thước
#     #                 attr_type = int.from_bytes(mft_entry[offset:offset + 4], "little")
#     #                 attr_len = int.from_bytes(mft_entry[offset + 4:offset + 8], "little")

#     #                 if attr_type == 0xFFFFFFFF:  # Hết danh sách attribute
#     #                     break

#     #                 # Attribute $FILE_NAME
#     #                 if attr_type == 48:
#     #                     content_offset = offset + int.from_bytes(mft_entry[offset + 20:offset + 22], "little")
#     #                     name_len = mft_entry[content_offset + 64]  # Độ dài tên file (UTF-16)
#     #                     name_offset = content_offset + 66

#     #                     # Lấy tên file theo UTF-16
#     #                     filename = mft_entry[name_offset:name_offset + (name_len * 2)].decode("utf-16le", errors="ignore")

#     #                 # Attribute $DATA
#     #                 if attr_type == 128:  # Attribute $DATA
#     #                     content_offset = offset + int.from_bytes(mft_entry[offset + 20:offset + 22], "little")
#     #                     real_size = int.from_bytes(mft_entry[content_offset + 48:content_offset + 56], "little")
#     #                     file_size = real_size

#     #                 offset += attr_len  # Chuyển sang attribute tiếp theo

#     #             if file_size == None:
#     #                 continue

#     #             print(f"Scanning: Filename: {filename}, size: {byte_converter(file_size)}")
#     #             deleted_files.append({
#     #                 "name": filename,
#     #                 "file_size": file_size,
#     #                 "first_offset": offset_entry
#     #             })

#     #             entry_number += 1  # Chuyển sang entry tiếp theo

#     #         except:
#     #             # Kết thúc nếu không đọc được entry tiếp theo
#     #             break

#     #     return deleted_files

#     # def scan_full(self):
#     #     return self.scan_quick()
    
#     # def recover_data(self, path, item):
#     #     """
#     #     Phục hồi file đã xóa từ thông tin item.
#     #     item bao gồm:
#     #     - name: Tên file
#     #     - file_size: Kích thước file
#     #     - first_offset: Offset của MFT entry chứa file
#     #     """
#     #     filename = item.get("name")
#     #     file_size = item.get("file_size")
#     #     file_offset = item.get("first_offset")

#     #     if not filename or file_size is None or file_offset is None:
#     #         raise ValueError("Thiếu thông tin trong item để phục hồi.")

#     #     # Đọc MFT entry từ first_offset
#     #     mft_entry = read_offset_in_hex(self.disk, file_offset, 1024)

#     #     # Kiểm tra chữ ký 'FILE' trong entry
#     #     if mft_entry[:4] != b"FILE":
#     #         raise ValueError(f"Entry tại offset {file_offset} không hợp lệ.")

#     #     # Kiểm tra Runlist trong $DATA
#     #     offset = int.from_bytes(mft_entry[0x14:0x16], "little")
#     #     runlist = None

#     #     while offset < 1024:
#     #         attr_type = int.from_bytes(mft_entry[offset:offset + 4], "little")
#     #         attr_len = int.from_bytes(mft_entry[offset + 4:offset + 8], "little")

#     #         if attr_type == 0xFFFFFFFF:  # Hết danh sách attribute
#     #             break

#     #         if attr_type == 128:  # Attribute $DATA
#     #             content_offset = offset + int.from_bytes(mft_entry[offset + 20:offset + 22], "little")
#     #             runlist_offset = content_offset + 0x10  # Runlist bắt đầu sau 0x10 bytes
#     #             runlist = mft_entry[runlist_offset:runlist_offset + (attr_len - 0x10)]
#     #             break

#     #         offset += attr_len

#     #     if not runlist:
#     #         raise ValueError(f"Không tìm thấy Runlist trong $DATA của file {filename}.")

#     #     # Giải mã Runlist
#     #     runs = self.decode_runlist(runlist)
#     #     recovered_size = 0

#     #     # Mở file để ghi dữ liệu phục hồi
#     #     with open(path, "wb") as output_file:
#     #         for run in runs:
#     #             start_cluster, cluster_count = run
#     #             start_offset = self.begin + start_cluster * self.cluster_size
#     #             run_size = cluster_count * self.cluster_size

#     #             if recovered_size + run_size > file_size:
#     #                 run_size = file_size - recovered_size  # Giới hạn nếu run vượt quá file_size

#     #             # Đọc dữ liệu từ ổ đĩa và ghi vào file
#     #             data = read_offset_in_hex(self.disk, start_offset, run_size)
#     #             output_file.write(data)
#     #             recovered_size += run_size

#     #             # Kiểm tra nếu đã phục hồi đủ dữ liệu
#     #             if recovered_size >= file_size:
#     #                 break

#     def decode_runlist(self, runlist):
#         """
#         Giải mã Runlist từ $DATA để lấy danh sách các đoạn dữ liệu (cluster).
#         """
#         runs = []
#         index = 0
#         last_cluster = 0

#         while index < len(runlist):
#             header = runlist[index]
#             if header == 0x00:  # Kết thúc Runlist
#                 break

#             # Đọc size, offset size từ header
#             cluster_size_len = header & 0x0F
#             cluster_offset_len = (header >> 4) & 0x0F
#             index += 1

#             # Đọc cluster size và cluster offset
#             cluster_size = int.from_bytes(runlist[index:index + cluster_size_len], "little", signed=False)
#             cluster_offset = int.from_bytes(runlist[index + cluster_size_len:index + cluster_size_len + cluster_offset_len], "little", signed=True)
#             index += cluster_size_len + cluster_offset_len

#             # Tính toán vị trí cluster thực
#             start_cluster = last_cluster + cluster_offset
#             runs.append((start_cluster, cluster_size))

#             # Lưu cluster cuối để tính toán giá trị tiếp theo
#             last_cluster = start_cluster

#         return runs
