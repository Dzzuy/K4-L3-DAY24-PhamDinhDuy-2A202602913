# Baseline — checkpoint 1 (đọc code)

1. **Agent có identity mỗi run chưa?** Chưa. Trong run_once() có nhận principal_id nhưng biến này chỉ được truyền vào runner.handle(). Nếu runner chưa được triển khai thì code sẽ chạy qua _naive_loop(message, llm) chứ không truyền theo principal_id, agent_id hay run_id (agent/loop.py:57-74). _naive_loop() cũng chưa có phần tạo hoặc kiểm tra danh tính agent (agent/loop.py:27-44).
2. **Ai cho phép `http_post`?**
Baseline chưa có bước nào kiểm tra quyền gửi dữ liệu. Trong _naive_loop(), agent lấy chỉ thị từ nội dung ticket thông qua llm.find_injection(), sau đó đọc các customer_ids được nhắc đến và gọi tools.http_post() nếu tìm thấy dữ liệu (agent/loop.py:31-44).
Trong agent/tools.py:76-84, URL chỉ được giới hạn ở localhost 127.0.0.1:10024. Tuy nhiên, phần này chỉ kiểm tra nơi gửi đến chứ cũng không kiểm tra agent có được phép gửi dữ liệu đó hay không.


3. **Nếu gửi sai PII ra sink, bằng chứng ở đâu?**
Trong agent/loop.py:37-44, dữ liệu khách hàng sau khi đọc sẽ được gom lại thành body {"records": collected}. Sau đó, tools.http_post() gửi body này bằng requests.post(..., json=body) (agent/tools.py:68-85).
Phía sink sẽ ghi lại từng request POST vào file reports/sink.log, gồm path và body (sink/sink.py:36-47).
