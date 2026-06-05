# ForensicsLab — Hệ Thống Thực Hành Điều Tra Số (Digital Forensics Lab)

ForensicsLab là một nền tảng thực hành trực tuyến dành cho các bài lab điều tra số (Digital Forensics). Hệ thống cho phép sinh viên thực hiện phân tích chứng cứ số thực tế ngay trên trình duyệt thông qua giao diện Web Terminal, tích hợp môi trường container hóa an toàn.

---

## 🚀 Tính Năng Chính

* **Bài Lab Đa Dạng (Lab Scenarios):**
  * **Network Forensics (Lab 1):** Phân tích lưu lượng mạng (File `.pcapng`), phát hiện SQL Injection, Brute Force.
  * **Disk Forensics (Lab 2):** Khôi phục dữ liệu đã xóa trên ảnh đĩa ảo (File `.E01`), trích xuất thông tin backdoor.
  * **Memory Forensics (Lab 3):** Phân tích RAM dump (File `.vmem`), điều tra tiến trình ẩn và kết nối C2 độc hại.
* **Sandbox Terminal Thông Minh:**
  * **Chế độ Docker Live:** Khởi tạo container Kali Linux riêng biệt, cô lập và an toàn cho mỗi sinh viên để chạy các công cụ thật (`tshark`, `volatility`, `sleuthkit/fls/icat`, `xxd`, `strings`...).
  * **Chế độ Giả lập (Simulated Mode):** Tự động kích hoạt khi máy chủ không cài Docker, giúp sinh viên làm quen cú pháp mà không tốn tài nguyên hệ thống.
* **Quản Lý Học Tập (LMS):**
  * **Dashboard Giáo Viên:** Giám sát thời gian thực danh sách lệnh sinh viên đã thực thi, chấm điểm báo cáo điều tra, quản lý chuỗi hành trình chứng cứ (Chain of Custody).
  * **Dashboard Sinh Viên:** Tải file chứng cứ, kích hoạt Sandbox, trả lời Flag trực tiếp để nhận điểm tự động.

---

## 🛠️ Yêu Cầu Hệ Thống

1. **Python 3.8+**
2. **Docker Desktop** hoặc **Docker Engine** (Tùy chọn, cần để kích hoạt Terminal Sandbox thật).

---

## ⚙️ Hướng Dẫn Cài Đặt & Khởi Chạy

### Bước 1: Cài đặt các thư viện Python
Mở Command Prompt/Terminal tại thư mục dự án và chạy:
```bash
pip install flask flask-wtf werkzeug docker
```

### Bước 2: Sinh dữ liệu chứng cứ số (Evidence Files)
Chạy script để sinh tự động các file PCAP, ổ đĩa ảo E01, RAM vmem mẫu:
```bash
python generate_evidence.py
```
*Sau khi chạy, các file chứng cứ sẽ nằm trong thư mục `static/evidence/`.*

### Bước 3: Build Docker Image cho Sandbox (Tùy chọn)
Nếu bạn muốn sử dụng tính năng **Terminal Live** thực tế, hãy khởi động Docker Desktop và chạy lệnh sau để build image:
```bash
docker build -f Dockerfile.forensics -t forensicslab:latest .
```
*(Nếu bỏ qua bước này, hệ thống sẽ tự động chạy Terminal ở chế độ Giả lập/Simulated).*

### Bước 4: Khởi chạy ứng dụng Web
Chạy file chạy chính:
```bash
python app.py
```
Ứng dụng sẽ chạy tại địa chỉ: `http://localhost:5000` (hoặc `http://<IP_Máy_Chủ>:5000` đối với các máy trong mạng nội bộ).

---

## 🔐 Tài Khoản Mặc Định (Đã Seed Sẵn)

Hệ thống đã chuẩn bị sẵn cơ sở dữ liệu mẫu `forensicslab.db` với hai tài khoản sau:

1. **Tài khoản Giáo viên:**
   * **Username:** `giaovien@haui.edu.vn`
   * **Password:** `admin123`
2. **Tài khoản Sinh viên:**
   * **Username:** `sinhvien@haui.edu.vn`
   * **Password:** `kali`

---

## 📁 Cấu Trúc Mã Nguồn

```text
ForensicsLab/
├── app.py                     # File chạy chính của ứng dụng Flask (API endpoints, Auth, DB)
├── sandbox_manager.py         # Module quản lý Container Docker Sandbox (Start, Stop, Exec)
├── generate_evidence.py       # Script sinh các file chứng cứ số (PCAP, Disk E01, RAM dump)
├── Dockerfile.forensics       # Cấu hình môi trường Kali Linux cho Docker Sandbox
├── docker-entrypoint.sh       # Script khởi động bên trong Docker container
├── forensicslab.db            # Cơ sở dữ liệu SQLite (Lưu thông tin tài khoản, câu hỏi, điểm số)
├── templates/                 # Các file giao diện HTML (Jinja2 templates)
└── static/                    # Các file tĩnh (CSS, JS, hình ảnh và tệp chứng cứ số)
```
