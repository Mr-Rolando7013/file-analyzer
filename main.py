import sys
import magic
import os
import hashlib
import pathlib
import datetime
import subprocess
import math
import yara
import re
import json
from packaging import version
# Get entry point
from elftools.elf.elffile import ELFFile
# Extract imported functions
from elftools.elf.enums import ENUM_ST_INFO_TYPE

packers = ['AHTeam', 'Armadillo', 'Stelth', 'yodas', 'ASProtect', 'ACProtect', 'PEnguinCrypt', 
 'UPX', 'Safeguard', 'VMProtect', 'Vprotect', 'WinLicense', 'Themida', 'WinZip', 'WWPACK',
 'Y0da', 'Pepack', 'Upack', 'TSULoader'
 'SVKP', 'Simple', 'StarForce', 'SeauSFX', 'RPCrypt', 'Ramnit', 
 'RLPack', 'ProCrypt', 'Petite', 'PEShield', 'Perplex',
 'PELock', 'PECompact', 'PEBundle', 'RLPack', 'NsPack', 'Neolite', 
 'Mpress', 'MEW', 'MaskPE', 'ImpRec', 'kkrunchy', 'Gentee', 'FSG', 'Epack', 
 'DAStub', 'Crunch', 'CCG', 'Boomerang', 'ASPAck', 'Obsidium','Ciphator',
 'Phoenix', 'Thoreador', 'QinYingShieldLicense', 'Stones', 'CrypKey', 'VPacker',
 'Turbo', 'codeCrypter', 'Trap', 'beria', 'YZPack', 'crypt', 'crypt', 'pack',
 'protect', 'tect'
]

potential_malicious_functions = ['system', 'execve', 'ptrace', 'prctl', 'dlopen', 'dlsym', 'socket', 'connect', 'fopen', 'read', 'write', 'libcrypt.so']

suspicious_sections = ['.textbss', '.dataenc', '.upx0', '.upx1', '.aspack', '.petite', '.themida', '.vmp0', '.vmp1', 'upx', '.xyz', '.packed', '.ab', '.secret', '.evil', '.payload']

def calculate_entropy(data):
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    entropy = 0.0
    data_length = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / data_length
        entropy -= probability * math.log2(probability)
    return entropy

def get_imported_functions(elf):
    imports = set()
    # PLT relocations
    for section_name in ('.rela.plt', '.rel.plt'):
        sec = elf.get_section_by_name(section_name)
        if not sec:
            continue
        symtab = elf.get_section(sec['sh_link'])

        for rel in sec.iter_relocations():
            sym = symtab.get_symbol(rel['r_info_sym'])
            if sym.name:
                imports.add(sym.name)
                    
        return sorted(imports)
    
def analyze_compiler_version(comment_data):
    alerts = []
    details = []
    compiler_detected = False

    comment = comment_data.lower()
    print("COMMENT: ", comment)

    if 'gcc' in comment:
        compiler_detected = True
        match = re.search(r'(\d+\.\d+(?:\.\d+)?)', comment)
        if match:
            v = version.parse(match.group(1))
            details.append(f"GCC version detected: {v}")
            
            if v < version.parse("10.0.0"):
                alerts.append("Heuristic Alert: Outdated GCC version detected.")
            else:
                details.append("GCC version is up to date.")
    if 'clang' in comment:
        compiler_detected = True
        match = re.search(r'(\d+\.\d+(?:\.\d+)?)', comment)
        if match:
            v = version.parse(match.group(1))
            details.append(f"Clang version detected: {v}")
            if v < version.parse("12.0.0"):
                alerts.append("Heuristic Alert: Outdated Clang version detected.")
            else:
                details.append("Clang version is up to date.")

    if 'rustc' in comment:
        compiler_detected = True
        details.append("Compiled with Rust compiler.")
        alerts.append("Heuristic Alert: Rust compiled binaries require further analysis.")

    if 'go' in comment or 'golang' in comment:
        compiler_detected = True
        details.append("Compiled with Go compiler.")
        alerts.append("Heuristic Alert: Go compiled binaries require further analysis.")

    if not compiler_detected:
        details.append("Compiler not identified or not in known list.")
        alerts.append("Heuristic Alert: Unknown compiler used.")
    
    return alerts, details


def main():
    input_file = sys.argv[1]
    mime = magic.from_buffer(open(input_file, 'rb').read(2048))
    print(f"MIME type of '{input_file}': {mime}")
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    with open(input_file, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
            hash_sha256.update(chunk)

    print(f"MD5: {hash_md5.hexdigest()}")
    print(f"SHA1: {hash_sha1.hexdigest()}")
    print(f"SHA256: {hash_sha256.hexdigest()}")

    # File size
    file_size = os.path.getsize(input_file)
    print(f"File size: {file_size} bytes")

    # File permissions
    file_permissions = oct(os.stat(input_file).st_mode)[-3:] # Interesting. If this causes issues, consider changing the implementation.
    print(f"File permissions: {file_permissions}")

    # Is executable is a flaw concept, but this is just has executable rights.
    is_executable = os.access(input_file, os.X_OK)
    print(f"Is executable: {is_executable}")

    # Get file creation and modification timestamps
    creation_time = datetime.datetime.fromtimestamp(os.path.getctime(input_file))
    modification_time = datetime.datetime.fromtimestamp(os.path.getmtime(input_file))
    print(f"Creation time: {creation_time}")
    print(f"Modification time: {modification_time}")

    if 'elf' in mime.lower():
        # Get strings
        file_strings = subprocess.run(["strings", input_file], capture_output=True, text=True)
        print(f"Strings in ELF file:\n{file_strings.stdout}")

    # Calculate entropy
    with open(input_file, 'rb') as f:
        file_data = f.read()
    entropy = calculate_entropy(file_data)
    print(f"Entropy: {entropy:.4f} bits/byte")

    # Detect packed binaries
    rules_path = "/mnt/c/Users/byL0r3t/Desktop/pythonProjects/file-analyzer/yaraRules"

    # Read yar files
    peid_rules = yara.compile(rules_path + "/peid.yar")
    packer_rules = yara.compile(rules_path + "/packer.yar")
    crypto_rules = yara.compile(rules_path + "/crypto_signatures.yar")

    try:
        matches = crypto_rules.match(input_file)
        if matches:
            print("Crypto signatures detected:")
            for match in matches:
                print(f" - {match.rule}")
        else:
            print("No crypto signatures detected.")
    except:
        print("Error scanning for crypto signatures.")
    
    # detect packers
    try:
        matches = packer_rules.match(input_file)
        if matches:
            print("Packers detected:")
            for match in matches:
                print(f" - {match.rule}")
        else:
            print("No packers detected.")
    except:
        print("Error scanning for packers.")

    try:
        matches = peid_rules.match(input_file)
        if matches:
            for match in matches:
                for packer in packers:
                    if packer.lower() in match.rule.lower():
                        print(f"PEiD signature detected: {match.rule}")
        else:
            print("No PEiD signatures detected.")
    except:
        print("Error scanning for PEiD signatures.")

    sections = []
    comment_section_data = None
    is_note_gnu_build_id = False
    segments = []
    heuristic_suspicious_section = None
    data_section_flag = None
    lacking_sections = []
    is_symtab = False
    is_strtab = False
    is_comment = False
    load_ranges = []
    heuristic_section_outside_segment = None

    with open(input_file, 'rb') as f:
        elf = ELFFile(f)
        entry_point = elf.header.e_entry
        print(f"Entry point address: {hex(entry_point)}")
        # Header section
        header_section = elf.header
        print(f"ELF Header: {header_section}")
        # Header table
        for segment in elf.iter_segments():
            temp_segment = {
                'p_type': segment['p_type'],
                'p_offset': segment['p_offset'],
                'p_vaddr': segment['p_vaddr'],
                'p_paddr': segment['p_paddr'],
                'p_filesz': segment['p_filesz'],
                'p_memsz': segment['p_memsz'],
                'p_flags': segment['p_flags'],
                'p_align': segment['p_align']
            }
            segments.append(temp_segment)
            print(f"Segment: Type: {segment['p_type']}, Virtual Address: {hex(segment['p_vaddr'])}, Size in File: {segment['p_filesz']} bytes")
            start = segment['p_vaddr']
            end = start + segment['p_memsz']
            load_ranges.append((start, end))
        # Section headers
        for section in elf.iter_sections():
            temp_section = {
                'sh_name': section.name,
                'sh_type': section['sh_type'],
                'sh_flags': section['sh_flags'],
                'sh_addr': section['sh_addr'],
                'sh_offset': section['sh_offset'],
                'sh_size': section['sh_size'],
                'sh_link': section['sh_link'],
                'sh_info': section['sh_info'],
                'sh_addralign': section['sh_addralign'],
                'sh_entsize': section['sh_entsize']
            }
            sections.append(temp_section)
            
            print(f"Section: {section.name}, Size: {section.data_size} bytes, Type: {section['sh_type']}, Flags: {section['sh_flags']}")

            if section.name == '.comment':
                is_comment = True
                comment_section_data = section.data()

            if section.name == '.note.gnu.build-id':
                is_note_gnu_build_id = True

            if section.name in suspicious_sections:
                heuristic_suspicious_section = section.name
                print(f"Heuristic Alert: Suspicious section detected - {section.name}")

            if section.name == '.data':
                data_section_flag = section['sh_flags']

            if section.name == '.symtab':
                is_symtab = True

            if section.name == '.strtab':
                is_strtab = True

            # check if inside any segment
            if not any(start <= section['sh_addr'] < end for start, end in load_ranges):
                heuristic_section_outside_segment = f"Heuristic Alert: Section {section.name} is not mapped in any segment."


        # Imported functions - Needs better testing
        functions = get_imported_functions(elf)
        print("Imported functions:")
        for func in functions:
            print(f"Function: - {func}")

    # Heuristics of functions
    malicious_imports = [func for func in functions if func in potential_malicious_functions]

    # Heuristics of sections
    # TO do Unusal debug notes .notes?

    # Missing .note.gnu.build-id
    if not is_note_gnu_build_id:
        print("Heuristic Alert: Missing .note.gnu.build-id section.")

    # .comment compiler analysis
    compiler = comment_section_data.decode(errors='ignore')
    print(f"Comment Section Data: {comment_section_data.decode(errors='ignore')}")
    compiler_alerts, compiler_details = analyze_compiler_version(compiler)

    # Heuristic for entropy?

    # .data is writable?
    if data_section_flag is not None:
        if data_section_flag & 0x2:  # SHF_WRITE
            alert_writable_data_section = "Heuristic Alert: .data section is writable."

    # Stripped or manipulated binaries - missing manipulated?
    if not is_symtab:
        lacking_sections.append('.symtab')
    if not is_strtab:
        lacking_sections.append('.strtab')
    if not is_comment:
        lacking_sections.append('.comment')

    # Sections with anomalies - done

    # Overlapping section addresses - to do

    # Sections huge in size but tiny in file offset - to do

    # Entry point outside .text section - to do

    # .text section size extremely small - to do

    """ Extra Anti-Analysis Features to consider later
    - Anti-debugging techniques
    - Anti-Disassembly techniques
    - Self-modifying code
    - Obfuscated strings
    - Encrypted config blobs
    - Custom loaders embedded in .rodata"""


if __name__ == "__main__":
    main()