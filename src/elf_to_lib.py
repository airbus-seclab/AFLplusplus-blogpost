#!/usr/bin/env python3
import lief

# See https://lief-project.github.io/doc/latest/tutorials/08_elf_bin2lib.html
target = lief.parse("target")

# Add the 'parse_cert' function to export table and save the ELF to a new file
parse_cert = next(filter(lambda f: f.name == "parse_cert", target.functions))
target.add_exported_function(parse_cert.address, parse_cert.name)
target.write("libtarget.so")
