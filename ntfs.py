import struct
import sys
import os


def read_boot_sector(disk_path):
    with open(disk_path, "rb") as f:
        return f.read(512)


def parse_boot_sector(boot_sector):
    # Lấy số byte/sector (offset 11, 2 byte, little-endian)
    bytes_per_sector = struct.unpack_from("<H", boot_sector, 11)[0]
    # Lấy số sector/cluster (offset 13, 1 byte)
    sectors_per_cluster = struct.unpack_from("B", boot_sector, 13)[0]
    cluster_size = bytes_per_sector * sectors_per_cluster
    # Lấy số cluster của $MFT (offset 48, 8 byte little-endian, có dấu)
    mft_cluster = struct.unpack_from("<q", boot_sector, 48)[0]
    return bytes_per_sector, sectors_per_cluster, cluster_size, mft_cluster


def read_mft_entry(disk_path, mft_offset, record_index, entry_size=1024):
    with open(disk_path, "rb") as f:
        f.seek(mft_offset + record_index * entry_size)
        return f.read(entry_size)


def parse_mft_record(record):
    # Kiểm tra signature: phải bắt đầu bằng b'FILE'
    signature = record[0:4]
    if signature != b"FILE":
        return None
    sequence = struct.unpack_from("<H", record, 4)[0]
    flags = struct.unpack_from("<H", record, 22)[0]

    return {"signature": signature, "sequence": sequence, "flags": flags}


def parse_data_runs(data):
    runs = []
    pos = 0
    last_lcn = 0
    while pos < len(data):
        header = data[pos]
        pos += 1
        if header == 0:
            break
        length_size = header & 0x0F
        offset_size = (header >> 4) & 0x0F

        # Đọc run length
        run_length = int.from_bytes(data[pos : pos + length_size], "little")
        pos += length_size

        # Xử lý sparse run (offset_size = 0)
        if offset_size == 0:
            runs.append((None, run_length))  # Đánh dấu sparse run
            continue

        # Đọc run offset
        run_offset = int.from_bytes(
            data[pos : pos + offset_size], byteorder="little", signed=True
        )
        pos += offset_size

        # Tính absolute LCN
        if not runs:
            lcn = run_offset  # Run đầu: absolute
        else:
            lcn = last_lcn + run_offset  # Run sau: relative

        runs.append((lcn, run_length))
        last_lcn = lcn
    return runs


def get_file_name(record):
    """
    Quét qua các attribute của bản ghi MFT để tìm attribute $FILE_NAME (type 0x30).
    Trong attribute resident, tại offset 64 chứa độ dài file name (số ký tự),
    sau đó file name (mã hóa UTF-16LE) bắt đầu từ offset 66.
    """
    first_attr_offset = struct.unpack_from("<H", record, 20)[0]
    pos = first_attr_offset
    while pos < len(record):
        attr_type = struct.unpack_from("<I", record, pos)[0]
        if attr_type == 0 or attr_type == 0xFFFFFFFF:
            break
        attr_length = struct.unpack_from("<I", record, pos + 4)[0]
        # Nếu attribute $FILE_NAME (type 0x30)
        if attr_type == 0x30:
            non_resident_flag = record[pos + 8]
            if non_resident_flag == 0:  # resident attribute
                content_length = struct.unpack_from("<I", record, pos + 16)[0]
                content_offset = struct.unpack_from("<H", record, pos + 20)[0]
                content_start = pos + content_offset
                # Kiểm tra độ dài tối thiểu để chứa thông tin file name
                if content_length >= 66:
                    file_name_length = record[content_start + 64]
                    name_bytes = record[
                        content_start + 66 : content_start + 66 + file_name_length * 2
                    ]
                    try:
                        filename = name_bytes.decode("utf-16le")
                        return filename
                    except Exception as e:
                        return None
            else:
                # Thông thường $FILE_NAME được lưu resident
                pass
        pos += attr_length
    return None


def list_deleted_files(disk_path, mft_offset, total_records, cluster_size):
    """
    Quét qua các bản ghi MFT từ 0 đến total_records.
    Với mỗi bản ghi hợp lệ (có signature 'FILE') mà flag không chứa bit 0x0001 (allocated)
    => xem là file đã xóa.
    In ra số thứ tự bản ghi, tên file và phần mở rộng (nếu có).
    """
    print("\n--- Danh sách file đã xóa ---")
    for record_index in range(total_records):
        record = read_mft_entry(disk_path, mft_offset, record_index)
        hdr = parse_mft_record(record)
        if hdr is None:
            continue
        # Nếu flag có bit 0x0001, tức file đang được phân bổ => không bị xóa
        if hdr["flags"] & 0x0001:
            continue
        filename = get_file_name(record)
        if filename is None or filename == "":
            continue
        # Lấy phần mở rộng file (nếu có)
        parts = filename.rsplit(".", 1)
        extension = parts[1] if len(parts) == 2 else ""
        print(f"Record {record_index}: {filename} (extension: {extension})")


def lznt1_decompress(src):
    """
    Một implement LZNT1 decompression đơn giản.
    LZNT1 nén dữ liệu theo từng chunk (tối đa 4096 byte).
    Chú ý: Đây là một phiên bản đơn giản, có thể không xử lý hết mọi trường hợp.
    """
    dest = bytearray()
    pos = 0
    src_len = len(src)
    # LZNT1 nén theo từng chunk, mỗi chunk có header 2 byte.
    while pos < src_len:
        # Nếu không đủ header thì thoát.
        if pos + 2 > src_len:
            break
        (chunk_header,) = struct.unpack_from("<H", src, pos)
        pos += 2
        # Lower 12 bit: kích thước chunk - 1
        chunk_size = (chunk_header & 0x0FFF) + 1
        # Nếu high bit được đặt, chunk là uncompressed
        is_compressed = (chunk_header & 0x8000) == 0
        if not is_compressed:
            # Chưa nén: copy chunk_size byte
            dest += src[pos : pos + chunk_size]
            pos += chunk_size
        else:
            # Chunk nén: xử lý cho đến hết chunk_size
            chunk_end = pos + chunk_size
            while pos < chunk_end:
                flag = src[pos]
                pos += 1
                for bit in range(8):
                    if pos >= chunk_end:
                        break
                    if flag & (1 << bit):
                        # Token 2 byte, copy từ dữ liệu đã được giải nén
                        if pos + 2 > chunk_end:
                            break
                        token = struct.unpack_from("<H", src, pos)[0]
                        pos += 2
                        copy_length = (token >> 12) + 3
                        copy_offset = token & 0x0FFF
                        for _ in range(copy_length):
                            if copy_offset > len(dest) or len(dest) == 0:
                                # Nếu offset không hợp lệ, append 0
                                dest.append(0)
                            else:
                                dest.append(dest[-copy_offset])
                    else:
                        # Literal byte: copy trực tiếp
                        dest.append(src[pos])
                        pos += 1
    return bytes(dest)


def recover_file_from_mft(
    disk_path, mft_offset, record_index, cluster_size, output_file
):
    record = read_mft_entry(disk_path, mft_offset, record_index)
    hdr = parse_mft_record(record)
    if hdr is None:
        print(f"Bản ghi MFT {record_index} không hợp lệ.")
        return

    # Nếu người dùng không nhập phần mở rộng cho file phục hồi, bổ sung vào output_file
    if not os.path.splitext(output_file)[1]:
        fname = get_file_name(record)
        if fname:
            parts = fname.rsplit(".", 1)
            if len(parts) == 2 and parts[1]:
                ext = parts[1]
                output_file = output_file + "." + ext
                print(f"Đã bổ sung phần mở rộng vào file phục hồi: {output_file}")

    print(
        f"\nĐang xử lý bản ghi MFT {record_index}: sequence {hdr['sequence']} flags {hdr['flags']}"
    )

    # Quét qua các attribute từ offset được chỉ định ở byte 20
    first_attr_offset = struct.unpack_from("<H", record, 20)[0]
    pos = first_attr_offset
    data_runs = None
    real_size = None
    comp_unit = 0  # Compression Unit; nếu != 0, file được nén
    while pos < len(record):
        attr_type = struct.unpack_from("<I", record, pos)[0]
        if attr_type == 0 or attr_type == 0xFFFFFFFF:
            break
        attr_length = struct.unpack_from("<I", record, pos + 4)[0]
        non_resident_flag = record[pos + 8]
        # Tìm attribute $DATA (type 0x80)
        if attr_type == 0x80:
            if non_resident_flag == 1:
                data_run_offset = struct.unpack_from("<H", record, pos + 32)[0]
                comp_unit = struct.unpack_from("<H", record, pos + 34)[0]
                real_size = struct.unpack_from("<Q", record, pos + 48)[0]
                data_runs_data = record[pos + data_run_offset : pos + attr_length]
                data_runs = parse_data_runs(data_runs_data)
                print(
                    "Data runs:",
                    data_runs,
                    "Real file size:",
                    real_size,
                    "Compression Unit:",
                    comp_unit,
                )
                break
            else:
                resident_data_length = struct.unpack_from("<I", record, pos + 16)[0]
                resident_data_offset = struct.unpack_from("<H", record, pos + 20)[0]
                data = record[
                    pos
                    + resident_data_offset : pos
                    + resident_data_offset
                    + resident_data_length
                ]
                with open(output_file, "wb") as f:
                    f.write(data)
                print("File (resident) phục hồi thành công tại:", output_file)
                return
        pos += attr_length

    if data_runs is None:
        print(
            f"Không tìm thấy attribute $DATA non-resident trong bản ghi MFT {record_index}."
        )
        return

    if real_size is None:
        print("Không lấy được kích thước file thực (real size).")
        return

    # Đọc dữ liệu thô từ data runs
    raw_data = bytearray()
    remaining = real_size
    with open(disk_path, "rb") as disk:
        for lcn, run_length in data_runs:
            # Xử lý sparse run nếu có (lcn is None)
            if lcn is None:
                raw_data += b"\x00" * (run_length * cluster_size)
                remaining -= run_length * cluster_size
                if remaining <= 0:
                    break
                continue

            offset = lcn * cluster_size
            byte_length = run_length * cluster_size
            to_read = min(byte_length, remaining)
            print(
                f"Đang đọc data run: LCN={lcn}, length={run_length} clusters, offset={offset}, bytes={to_read}"
            )
            disk.seek(offset)
            chunk = disk.read(to_read)
            raw_data += chunk
            remaining -= len(chunk)
            if remaining <= 0:
                break

    # Nếu file được nén NTFS (comp_unit != 0), giải nén dữ liệu
    if comp_unit != 0:
        print("File được nén NTFS, thực hiện giải nén LZNT1.")
        decompressed_data = lznt1_decompress(raw_data)
    else:
        decompressed_data = raw_data

    with open(output_file, "wb") as out:
        out.write(decompressed_data)
    print("File phục hồi thành công tại:", output_file)

    with open(output_file, "rb") as f:
        header = f.read(4)
    print("Header bytes:", header.hex())


def main(argv):
    # drive_letter = input("Nhập đường dẫn ổ đĩa (hoặc file ảnh đĩa): ").strip()
    drive_letter = argv[0]

    disk_path = rf"\\.\{drive_letter}"

    boot_sector = read_boot_sector(disk_path)
    bytes_per_sector, sectors_per_cluster, cluster_size, mft_cluster = (
        parse_boot_sector(boot_sector)
    )
    print("Bytes per sector:", bytes_per_sector)
    print("Sectors per cluster:", sectors_per_cluster)
    print("Cluster size:", cluster_size)
    print("$MFT cluster number:", mft_cluster)
    mft_offset = mft_cluster * cluster_size
    print("Calculated MFT offset:", mft_offset)

    while True:
        choice = (
            input(
                "\nNhập 'L' để liệt kê các file đã xóa, 'R' để phục hồi file theo record index, nhập bất kỳ để thoát: "
            )
            .strip()
            .upper()
        )
        if choice == "L":
            try:
                total = int(input("Nhập số lượng bản ghi MFT cần quét (ví dụ: 1000): "))
            except:
                total = 1000
            list_deleted_files(disk_path, mft_offset, total, cluster_size)
        elif choice == "R":
            try:
                record_index = int(
                    input("Nhập số thứ tự bản ghi MFT của file cần phục hồi: ")
                )
            except:
                print("Giá trị không hợp lệ.")
                sys.exit(1)
            output_file = input("Nhập tên file phục hồi đầu ra: ").strip()
            recover_file_from_mft(
                disk_path, mft_offset, record_index, cluster_size, output_file
            )
        else:
            exit()


if __name__ == "__main__":
    import sys
    exit(main(sys.argv[1:]))
