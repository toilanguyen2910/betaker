# 🛡️ BetHacker

> **AI-Powered Penetration Testing & Offensive Security Assistant**  
> Trợ lý AI dòng lệnh chuyên biệt cho kiểm thử bảo mật và an ninh mạng.

---

## 🚀 Tính Năng Chính (MVP)

* 🤖 **ReAct Agent Loop**: Tự động phân tích mục tiêu, lập kế hoạch dò quét, gọi công cụ và tổng hợp báo cáo.
* 🛡️ **Human-in-the-loop Gate**: Mọi lệnh shell đều hiển thị rõ ràng và hỏi quyền xác nhận `[Y/n]` của bạn trước khi thực thi.
* 🛑 **Safety Blacklist**: Tự động chặn các câu lệnh nguy hiểm gây phá hủy hệ thống (`rm -rf`, `format`, `del /f /s /q`, `shutdown`,...).
* 🌐 **Multi-Provider LLM**: Hỗ trợ Google Gemini, OpenAI, DeepSeek, OpenRouter thông qua file `.env`.
* 📁 **Workspace Management**: Quản lý đọc, ghi log scan và tệp tin trong thư mục `./workspace`.
* 🐳 **Docker-Ready**: Chuẩn bị sẵn `Dockerfile` (dựa trên Kali Linux Rolling) để đóng gói chạy container cách ly bất cứ khi nào bạn muốn.

---

## ⚡ Cài Đặt & Sử Dụng

### 1. Chuẩn bị môi trường (Chạy trên Host)

1. Sao chép file cấu hình mẫu `.env.example` thành `.env`:
   ```bash
   cp .env.example .env
   ```
2. Mở file `.env` và điền API Key của mô hình bạn muốn dùng:
   ```env
   LLM_PROVIDER=gemini
   LLM_MODEL=gemini-2.5-flash
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

3. Cài đặt các thư viện cần thiết:
   ```bash
   pip install -r requirements.txt
   ```

### 2. Khởi chạy BetHacker

```bash
python main.py
```

Khi chạy, giao diện dòng lệnh tương tác sẽ xuất hiện. Bạn có thể nhập mục tiêu như:
* `Hãy kiểm tra các cổng mở và công nghệ web trên scanme.nmap.org`
* `Phân tích xem địa chỉ IP 192.168.1.10 có chạy dịch vụ SMB hoặc HTTP không`

---

## 🐳 Chạy bằng Docker (Tùy chọn)

Nếu sau này bạn cài đặt Docker và muốn chạy biệt lập trong môi trường **Kali Linux**:

```bash
# Build image
docker build -t bethacker .

# Chạy container
docker run -it --rm -v ${PWD}/workspace:/app/workspace --env-file .env bethacker
```

---

## ⚖️ Tuyên Bố Trách Nhiệm (Disclaimer)

Công cụ này chỉ được phép sử dụng cho mục đích **nghiên cứu giáo dục, thi đấu CTF, hoặc kiểm thử bảo mật trên các hệ thống có văn bản cấp phép hợp pháp**. Tác giả không chịu trách nhiệm về bất kỳ hành vi lạm dụng nào.
