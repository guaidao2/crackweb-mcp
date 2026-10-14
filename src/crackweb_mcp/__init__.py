"""An MCP server for the crackweb CLI.

crackweb is a command-line tool. This package turns it into tools an agent can call:
the same binary, the same behaviour, with the shell quoting, the process lifetime and
the parsing of console output taken care of. Nothing here changes crackweb, and nothing
here reimplements any of it — the scanner stays the scanner.
"""

__version__ = "0.1.0"
