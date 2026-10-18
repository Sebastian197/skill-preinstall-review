import re
import sys

text = sys.argv[1] if len(sys.argv) > 1 else "18/10/2026"
print(re.sub(r"(\d{2})/(\d{2})/(\d{4})", r"\3-\2-\1", text))
