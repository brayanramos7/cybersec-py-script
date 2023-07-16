#!/usr/bin/env python3

"""
# NOTE, you must change the filename below for the rp++ output you want to process.
# This script does not take arguments in its current form. Sorry!
"""

import re

from pwn import p32, u32

bad_characters = b"\x00\x0a\x0d\x20"

worthy_regexes = [
    r"xchg (...), (...)",
    r"inc ...",
    r"dec ...",
    r"mov ..., ...",
    r"push ... ; pop ...",
    r"xor ..., ...",
    r"neg ...",
    r"mov ..., dword \[...\]",
    r"mov dword \[...\], ...",
    r"add ..., ...",
    r"sub ..., ...",
    r"pop ...",
    # r"add ..., 0x[a-f0-9]{1,8}",  # This tends to find a lot...
]


for index, regex in enumerate(worthy_regexes):
    worthy_regexes[index] = (
        "(0x[a-f0-9]{8}): " + regex + r" ; (ret\s+|retn 0x00\d+\s+|);"
    )

found = []
output = []
with open("rop_mona/full_rp_libspp.txt") as h:
    for line in h:
        line = line.strip()

        if re.match(r"0x[a-f0-9]{8}: ", line):
            for regex in worthy_regexes:
                if re.match(regex, line):
                    address, instructions = line.split(":")
                    for bad in bad_characters:

                        if bad in p32(int(address, 16)):
                            break
                    else:
                        instructions = instructions.strip()
                        instructions = instructions.replace("(1 found)", "")
                        instructions = instructions.strip()
                        instructions = instructions.rstrip(";")
                        instructions = instructions.strip()
                        instructions = instructions.replace(";", "and")
                        instructions = instructions.replace(",", "")
                        instructions = instructions.replace(" ", "_")
                        instructions = instructions.replace("[", "MEM_")
                        instructions = instructions.replace("]", "_ADDRESS")
                        instructions = instructions.rstrip("_and_ret")

                        # If we have something with a retn but already have a clean one
                        # don't use the retn
                        if "_and_retn_" in instructions:
                            instructions_base = instructions[
                                : instructions.index("_and_retn")
                            ]
                        else:
                            instructions_base = instructions

                        # Store this if we have not seen it before
                        if instructions_base not in found:
                            output.append(f"{instructions} = p32({address})")
                            found.append(instructions)
output.sort()
for out in output:
    var, val = out.split("=")
    print(f"{var:50} = {val}")