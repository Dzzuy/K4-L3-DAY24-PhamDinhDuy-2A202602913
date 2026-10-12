# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner và phiên bản:** Gitleaks 8.30.1, tải từ release chính thức và kiểm checksum trước khi chạy. Hook `gitleaks-system` pin `v8.30.1`; `pre-commit run --all-files` đã pass.
- **Commit chứa token giả:** `1bdd849922156c868a5ee9293d68f5b72e242d2c`.
- **Quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .` trả exit code 1 như dự kiến. Scanner thấy đúng 1 finding ở `lab-fake-secret.txt:1`, rule `lab24-synthetic-token`, trong commit trên. Giá trị token đã được che trong output; đây là token giả, vô hiệu của bài lab.
- **Quét file hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .` trả exit code 0, không có finding.
- **Nếu là credential thật:** thu hồi hoặc rotate ngay tại dịch vụ cấp token, kiểm log để tìm dấu hiệu bị dùng sai, rồi xử lý các bản sao trong lịch sử Git và nơi đã phát tán. Không chờ xóa file xong mới thu hồi.
- **Vì sao xóa file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** commit cũ vẫn giữ nội dung đã lộ, và người từng đọc có thể còn bản sao. Pin dependency và hook giúp kiểm thay đổi về sau; chúng không làm credential cũ mất hiệu lực. Bài lab này không dùng credential thật.
