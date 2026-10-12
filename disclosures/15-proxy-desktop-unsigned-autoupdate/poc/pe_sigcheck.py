import struct, sys
for path in sys.argv[1:]:
    d = open(path,'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    assert d[pe:pe+4] == b'PE\0\0'
    magic = struct.unpack_from('<H', d, pe+24)[0]
    dd_off = pe+24 + (112 if magic == 0x20b else 96)
    sec_rva, sec_size = struct.unpack_from('<II', d, dd_off + 4*8)
    print(f"{path}: PE32{'+' if magic==0x20b else ''} security_dir(offset={sec_rva:#x}, size={sec_size}) -> {'SIGNED' if sec_size else 'NO AUTHENTICODE SIGNATURE'}")
