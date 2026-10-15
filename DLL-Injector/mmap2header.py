import sys

def generate_byte_array_header(elf_path, output_header="lib_bytes.h"):
    try:
        with open(elf_path, 'rb') as f:
            data = f.read()

        with open(output_header, "w") as f:
            f.write("#pragma once\n\n")
            f.write("#include <vector>;\n")
            f.write("#include <windows.h>\n\n")
            f.write("std::vector<BYTE> loader_dll_bytes = {\n    ")
            
            for i, byte in enumerate(data):
                f.write(f"0x{byte:02x}, ")
                if (i + 1) % 16 == 0:
                    f.write("\n    ")
                    
            f.write("\n};\n")
            
        print(f"[+] Generated {output_header}, Size: {len(data)} bytes!")
        
    except Exception as e:
        print(f"[-] Failed to generate byte array header: {e}")


if __name__ == "__main__":
    generate_byte_array_header("Manual-Map.dll.x64", "mmap_x64.h")
    generate_byte_array_header("Manual-Map.dll.x86", "mmap_x86.h")
