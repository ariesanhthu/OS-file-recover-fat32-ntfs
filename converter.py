level_label = ["byte(s)", "KB", "MB", "GB", "TB", "PB"]

def byte_converter(byte):
    level = 0

    while(byte >= 1024.0):
        byte /= 1024
        level += 1
    return f"{byte:.2f} {level_label[level]}"

