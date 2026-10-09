# 🛡️ BetAker

> **AI-Powered Security Code Auditor & Automated Patching CLI Tool**  
> Trợ lý AI dòng lệnh chuyên sâu về kiểm toán an ninh mã nguồn và tự động tạo bản vá bảo mật.

---

## 🚀 Tính Năng Nổi Bật

* 🔍 **Bộ Quét Đa Ngôn Ngữ (Polyglot SAST)**: Hỗ trợ quét và phát hiện các lỗ hổng theo chuẩn **OWASP Top 10** trên **Python, JavaScript/TypeScript, Go, PHP**:
  * SQL Injection (SQLi)
  * Command Injection (CMDi)
  * Path Traversal
  * Insecure Deserialization
  * Hardcoded Secrets & API Keys
  * SSRF & Cross-Site Scripting (XSS)
* 📦 **Kiểm Tra Lỗ Hổng Phụ Thuộc (SCA)**: Tự động phân tích các tệp tin `requirements.txt` và `package.json` đối chiếu với cơ sở dữ liệu tư vấn CVE để cảnh báo các thư viện bị lỗi.
* 🤖 **AI Root Cause Analysis & Auto-Patching**: Kết nối với mô hình AI (**DeepSeek**, Gemini, OpenAI) để phân tích nguyên nhân gốc rễ và tự động sinh bản vá code an toàn.
* 🛡️ **An Toàn Tuyệt Đối Khi Vá Lỗi**:
  * Xem trước bảng so sánh khác biệt (**Unified Diff**).
  * Tự động tạo file sao lưu `.bak` trước khi ghi đè.
  * Hỗ trợ lệnh `/rollback` để hoàn tác code ngay lập tức nếu cần.
* 💻 **Giao Diện Rich Terminal CLI**: Bảng màu trực quan, phân loại mức độ rủi ro (Critical, High, Medium, Low), hỗ trợ các lệnh tương tác: `/audit`, `/deps`, `/rollback`, `/report`.
* ✅ **Hệ Thống Kiểm Thử Tự Động**: Tích hợp sẵn 176+ test cases E2E và adversarial probes với tỷ lệ thành công 100%.

---

## ⚡ Cài Đặt & Sử Dụng

### 1. Cài đặt môi trường

1. Sao chép file cấu hình mẫu `.env.example` thành `.env`:
   ```bash
   cp .env.example .env
   ```
2. Điền API Key trong file `.env` (ví dụ DeepSeek hoặc Gemini):
   ```env
   LLM_PROVIDER=deepseek
   LLM_MODEL=deepseek-chat
   DEEPSEEK_API_KEY=your_deepseek_api_key
   ```

3. Cài đặt các thư viện phụ thuộc:
   ```bash
   pip install -r requirements.txt
   ```

### 2. Khởi chạy BetAker

```bash
python main.py
```

### 3. Các lệnh điều khiển trong CLI:
* `/audit <đường_dẫn>`: Quét kiểm toán an ninh cho một file hoặc toàn bộ thư mục dự án.
* `/deps`: Quét các thư viện phụ thuộc để tìm CVE đã biết.
* `/rollback <file>`: Khôi phục lại file gốc từ bản sao lưu `.bak`.
* `/report`: Xuất báo cáo kiểm toán bảo mật chi tiết ra file Markdown trong thư mục workspace.
* `/help`: Hiển thị hướng dẫn sử dụng.
* `/exit`: Thoát chương trình.

---

## 🧪 Chạy Kiểm Thử Tự Động

```bash
pytest tests/
```

Toàn bộ 176 bài test sẽ được thực thi tự động để kiểm tra độ chính xác của bộ lọc SAST, bộ phân tích SemVer SCA, và cơ chế vá lỗi an toàn.

---

## 📄 Bản Quyền & Giấy Phép

Phát triển bởi [@toilanguyen2910](https://github.com/toilanguyen2910) - Được phát hành theo giấy phép MIT.
