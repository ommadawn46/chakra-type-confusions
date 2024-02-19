buf = b"\xCC\x90\x90\x90\x90\x90\x90\x90"

hexes = [hex(int.from_bytes(buf[i : i + 4], "little")) for i in range(0, len(buf), 4)]
print(f'const shellcode = [{", ".join(hexes)}];')
