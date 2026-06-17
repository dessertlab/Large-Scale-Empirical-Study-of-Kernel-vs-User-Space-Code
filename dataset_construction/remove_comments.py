import re

def remove_comments(code):
    
    """
        Remove C/C++ comments while preserving code structure
        after converting to ASCII to avoid encoding issues.

        Args:
            code: String containing C/C++ source code
        Returns:
            Code string with comments and excessive blank lines removed.
    """

    def to_ascii (code):
        # Keeps only ASCII characters (ord(char) < 128)
        return ''.join(char for char in code if ord(char) < 128)
    
    def remove_multiple_newlines(code):
        # Replaces any sequence of two or more newlines with a single newline
        # The 're.sub' pattern r'\n\s*\n+' matches:
        # \n       -> a newline
        # \s* -> zero or more whitespace characters (spaces, tabs, etc.)
        # \n+      -> one or more newlines (to catch the 'multiple \n' part)
        return re.sub(r'\n\s*\n+', '\n', code.strip())

    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            # Replace comment with space to preserve some formatting (e.g., separating tokens)
            return " "
        else:
            # Return string literals as-is
            return s
    
    # Pattern that matches both comment types and string/char literals
    # Literals are included to prevent accidentally removing // or /* inside them.
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    
    # 1. Convert to ASCII
    ascii_code = to_ascii(code)
    
    # 2. Remove comments
    code_no_comments = pattern.sub(replacer, ascii_code)
    
    # 3. Collapse multiple newlines into a single one
    final_code = remove_multiple_newlines(code_no_comments)
    
    return final_code