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
output_data = {}
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
    output_data['file_path'] = str(pathlib.Path(input_file).resolve())
    output_data['mime_type'] = mime
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
    output_data['md5'] = hash_md5.hexdigest()
    output_data['sha1'] = hash_sha1.hexdigest()
    output_data['sha256'] = hash_sha256.hexdigest()

    # File size
    file_size = os.path.getsize(input_file)
    print(f"File size: {file_size} bytes")
    output_data['file_size'] = file_size

    # File permissions
    file_permissions = oct(os.stat(input_file).st_mode)[-3:] # Interesting. If this causes issues, consider changing the implementation.
    print(f"File permissions: {file_permissions}")
    output_data['file_permissions'] = file_permissions

    # Is executable is a flaw concept, but this is just has executable rights.
    is_executable = os.access(input_file, os.X_OK)
    print(f"Is executable: {is_executable}")
    output_data['is_executable'] = is_executable

    # Get file creation and modification timestamps
    creation_time = datetime.datetime.fromtimestamp(os.path.getctime(input_file))
    modification_time = datetime.datetime.fromtimestamp(os.path.getmtime(input_file))
    print(f"Creation time: {creation_time}")
    print(f"Modification time: {modification_time}")
    # ISOFORMAT?
    output_data['creation_time'] = creation_time.isoformat()
    output_data['modification_time'] = modification_time.isoformat()

    if 'elf' in mime.lower():
        # Get strings
        file_strings = subprocess.run(["strings", input_file], capture_output=True, text=True)
        print(f"Strings in ELF file:\n{file_strings.stdout}")
        output_data['strings'] = file_strings.stdout.splitlines()

    # Calculate entropy
    with open(input_file, 'rb') as f:
        file_data = f.read()
    entropy = calculate_entropy(file_data)
    print(f"Entropy: {entropy:.4f} bits/byte")
    output_data['entropy'] = entropy

    # Detect packed binaries
    rules_path = "/mnt/c/Users/byL0r3t/Desktop/pythonProjects/file-analyzer/yaraRules"

    # Read yar files
    peid_rules = yara.compile(rules_path + "/peid.yar")
    packer_rules = yara.compile(rules_path + "/packer.yar")
    crypto_rules = yara.compile(rules_path + "/crypto_signatures.yar")

    try:
        matches = crypto_rules.match(input_file)
        if matches:
            output_data['crypto_signatures'] = [match.rule for match in matches]
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
            output_data['packers'] = [match.rule for match in matches]
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
                    output_data['peid_signatures'] = [match.rule for match in matches if packer.lower() in match.rule.lower()]
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
    heuristic_text_section_small = None
    heuristic_entry_point_outside_text = None
    heuristic_sections_huge_in_size_but_tiny_offset = []
    sections_overlap = None

    with open(input_file, 'rb') as f:
        elf = ELFFile(f)
        # get file size
        f.seek(0,2)
        file_size = f.tell()
        entry_point = elf.header.e_entry
        print(f"Entry point address: {hex(entry_point)}")
        output_data['entry_point'] = hex(entry_point)
        # Header section
        header_section = elf.header
        header_section_dict = {
            'e_type': header_section['e_type'],
            'e_machine': header_section['e_machine'],
            'e_version': header_section['e_version'],
            'e_entry': header_section['e_entry'],
            'e_phoff': header_section['e_phoff'],
            'e_shoff': header_section['e_shoff'],
            'e_flags': header_section['e_flags'],
            'e_ehsize': header_section['e_ehsize'],
            'e_phentsize': header_section['e_phentsize'],
            'e_phnum': header_section['e_phnum'],
            'e_shentsize': header_section['e_shentsize'],
            'e_shnum': header_section['e_shnum'],
            'e_shstrndx': header_section['e_shstrndx']
        }
        output_data['elf_header'] = header_section_dict
        print(f"ELF Header: {header_section}")
        exclude_sections = {0, 7, 8, 3, 4, 27, 29, 30}  # NULL, NOBITS, NOTE, .comment, .shstrtab, .strtab, etc.
        sections_overlap = [sec for sec in elf.iter_sections() if sec['sh_type'] not in exclude_sections and sec['sh_addr'] != 0]
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
            # Sections huge in size but tiny in file offset - done
            section_size = section['sh_size']
            section_offset = section['sh_offset']
            offset_treshold = (section_size * 10) // 100
            if section_offset < offset_treshold:
                heuristic_sections_huge_in_size_but_tiny_offset.append({'type': 'big_section_with_tiny_offset',
                                                              'name': section.name, 'size': section_size, 
                                                              'offset': section_offset, 
                                                              'offset_threshold': offset_treshold,
                                                              'severity': 'medium',
                                                              'reason': 'Section has a very small file offset compared to its size.'})
                print(f"Heuristic Alert: Section {section.name} has a very small file offset compared to its size.")

            if section.name == '.comment':
                is_comment = True
                comment_section_data = section.data()

            if section.name == '.note.gnu.build-id':
                is_note_gnu_build_id = True

            if section.name in suspicious_sections:
                heuristic_suspicious_section = {"type": "suspicious_section", 
                                                "section_name": section.name, 
                                                "severity": "medium", 
                                                "reason": "Section name is commonly used in packed or obfuscated binaries."}
                print(f"Heuristic Alert: Suspicious section detected - {section.name}")

            if section.name == '.data':
                data_section_flag = section['sh_flags']

            if section.name == '.symtab':
                is_symtab = True

            if section.name == '.strtab':
                is_strtab = True
            # Sections with anomalies - done
            # check if section is mapped inside any segment
            if not any(start <= section['sh_addr'] < end for start, end in load_ranges):
                heuristic_section_outside_segment = {"type": "section_outside_segment",
                                                     "section_name": section.name,
                                                     "severity": "high",
                                                     "reason": "Section is not mapped within any loadable segment."}

            if section.name == '.text':
                # Entry point outside .text section - done
                text_section_start = section['sh_addr']
                text_section_end = text_section_start + section['sh_size']
                if text_section_start <= entry_point and entry_point < text_section_end:
                    print(".text section contains the entry point.")
                else:
                    heuristic_entry_point_outside_text = {"type": "entry_point_outside_text",
                                                          "section_name": section.name,
                                                          "severity": "high",
                                                          "reason": "Entry point is outside the .text section."}
                text_section_size = section['sh_size']
                if text_section_size / file_size < 0.05:
                    # .text section size extremely small
                    heuristic_text_section_small = {"type": "text_section_too_small",
                                                    "section_name": section.name,
                                                    "severity": "medium",
                                                    "reason": ".text section size is less than 5% of total file size."}


        # Imported functions - Needs better testing
        functions = get_imported_functions(elf)
        print("Imported functions:")
        for func in functions:
            print(f"Function: - {func}")

    output_data['elf_sections'] = sections
    output_data['elf_segments'] = segments
    output_data['imported_functions'] = functions

    # Heuristics of functions
    malicious_imports = [func for func in functions if func in potential_malicious_functions]
    if malicious_imports:
        heuristic_malicious_imports = {'type': 'malicious_imports',
                                    'functions': malicious_imports,
                                    'severity': 'high',
                                    'reason': 'Presence of potentially malicious imported functions.'}

    # Heuristics of sections
    # TO do Unusal debug notes .notes?

    # Missing .note.gnu.build-id
    if not is_note_gnu_build_id:
        heuristic_missing_build_id = {'type': 'missing_build_id',
                                      'severity': 'low',
                                      'reason': 'The .note.gnu.build-id section is missing.'}
        print("Heuristic Alert: Missing .note.gnu.build-id section.")

    # .comment compiler analysis
    compiler = comment_section_data.decode(errors='ignore')
    print(f"Comment Section Data: {comment_section_data.decode(errors='ignore')}")
    heuristic_compiler_alerts, compiler_details = analyze_compiler_version(compiler)
    output_data['compiler_details'] = compiler_details
    if heuristic_compiler_alerts:
        heuristic_compiler_info = {'type': 'compiler_analysis',
                                   'alerts': heuristic_compiler_alerts,
                                   'severity': 'medium',
                                   'reason': 'Analysis of compiler version from .comment section.'}

    # Heuristic for entropy?

    # .data is writable?
    if data_section_flag is not None:
        if data_section_flag & 0x2:  # SHF_WRITE
            heuristic_writable_data_section = {'type': 'writable_data_section',
                                              'severity': 'medium',
                                              'reason': '.data section has write permissions.'}

    # Stripped or manipulated binaries - missing manipulated?
    if not is_symtab:
        lacking_sections.append('.symtab')
    if not is_strtab:
        lacking_sections.append('.strtab')
    if not is_comment:
        lacking_sections.append('.comment')

    if lacking_sections:
        heuristic_stripped_binary = {'type': 'stripped_binary',
                                     'missing_sections': lacking_sections,
                                     'severity': 'medium',
                                     'reason': 'The binary is missing standard sections, indicating it may be stripped.'}

    # Overlapping section addresses - to do
    overlappingSections = []
    for i, sec1 in enumerate(sections_overlap):
        for j, sec2 in enumerate(sections_overlap):
            if i >= j:
                continue

            start1, end1 = sec1['sh_addr'], sec1['sh_addr'] + sec1['sh_size']
            start2, end2 = sec2['sh_addr'], sec2['sh_addr'] + sec2['sh_size']
            if start1 < end2 and start2 < end1:
                overlappingSections.append({'section1': sec1['sh_name'], 'section2': sec2['sh_name'], 'section1_start': start1, 'section1_end': end1, 'section2_start': start2, 'section2_end': end2})

    if overlappingSections:
        heuristic_sections_overlap = {'type': 'overlapping_sections',
                                      'overlaps': overlappingSections,
                                      'severity': 'high',
                                      'reason': 'Sections have overlapping address ranges.'}
        
    output_data['heuristics'] = {
        'malicious_imports': heuristic_malicious_imports if 'heuristic_malicious_imports' in locals() else None,
        'suspicious_section': heuristic_suspicious_section,
        'missing_build_id': heuristic_missing_build_id if 'heuristic_missing_build_id' in locals() else None,
        'compiler_analysis': heuristic_compiler_info if 'heuristic_compiler_info' in locals() else None,
        'writable_data_section': heuristic_writable_data_section if 'heuristic_writable_data_section' in locals() else None,
        'stripped_binary': heuristic_stripped_binary if 'heuristic_stripped_binary' in locals() else None,
        'section_outside_segment': heuristic_section_outside_segment,
        'text_section_too_small': heuristic_text_section_small,
        'entry_point_outside_text': heuristic_entry_point_outside_text,
        'sections_huge_in_size_but_tiny_offset': heuristic_sections_huge_in_size_but_tiny_offset,
        'sections_overlap': heuristic_sections_overlap if 'heuristic_sections_overlap' in locals() else None
    }
    with open("data.json", "w") as file:
        json.dump(output_data, file, indent=4)

    """ Extra Anti-Analysis Features to consider later
    - Anti-debugging techniques
    - Anti-Disassembly techniques
    - Self-modifying code
    - Obfuscated strings
    - Encrypted config blobs
    - Custom loaders embedded in .rodata"""


if __name__ == "__main__":
    main()