"""
Utility to locate CLI tools (semgrep, bandit) regardless of how they were
installed — in a virtualenv, via pip --user, or system-wide.

Resolution order:
  1. Same directory as sys.executable  (covers virtualenv bin/)
  2. ~/.local/bin/                     (covers pip install --user on Linux/macOS)
  3. shutil.which()                    (honours the current PATH)
  4. /usr/local/bin/ and /usr/bin/     (common system-wide locations)
  5. Bare name as last resort          (let subprocess resolve it at runtime)
"""
import os
import sys
import shutil


def find_tool(name: str) -> str:
    """Return the best absolute path for *name*, or bare *name* as fallback."""
    candidates = []

    # 1. Sibling of the running Python interpreter (virtualenv / conda / pyenv)
    candidates.append(os.path.join(os.path.dirname(sys.executable), name))

    # 2. pip install --user location (Linux / macOS)
    candidates.append(os.path.expanduser(f'~/.local/bin/{name}'))

    # 3. PATH-based resolution
    which_path = shutil.which(name)
    if which_path:
        candidates.append(which_path)

    # 4. Common system-wide locations
    for prefix in ('/usr/local/bin', '/usr/bin', '/opt/homebrew/bin'):
        candidates.append(os.path.join(prefix, name))

    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    # Last resort — let the OS try to resolve it
    return name
