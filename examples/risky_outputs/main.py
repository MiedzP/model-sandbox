# Writes outputs that Windows could run, to test quarantine.
open("/out/report.exe", "wb").write(b"MZ\x90\x00" + b"\x00" * 60)   # PE header
open("/out/run_me.bat", "w").write("@echo off\necho hi\n")           # batch script
open("/out/payload.dat", "wb").write(b"\x7fELF" + b"\x00" * 60)       # ELF by content
open("/out/tool.sh", "w").write("#!/bin/sh\necho hi\n")               # shebang: flagged
open("/out/analysis.py", "w").write("print('hello')\n")               # script: flagged
open("/out/notes.txt", "w").write("plain text is fine\n")
print("written")
