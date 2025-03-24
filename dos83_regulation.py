import re

def is_dos_8_3(input):
    """
    Check this input string whether follow DOS 8.3 regulations
    """
    # Biểu thức chính quy kiểm tra ký tự hợp lệ
    valid_chars = re.compile(r'^[A-Z0-9!#$%&\'()\-\@^_{}~]+$') # Allow these characters only
    if not valid_chars.match(input):
        return False

    return True

