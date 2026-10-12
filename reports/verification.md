# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
- Các lỗi còn lại:

## CP2 — baseline và bốn lure (đã chạy)

- `python -m agent.check_lure corpus/ticket-90*.md`: **4/4 lure sẵn sàng**. Hai file của biến thể 4 riêng lẻ trả `None` từ `find_injection()` nhưng khi ghép lại, mock nhận 2 marker và trích `KH-000999`.
- Chạy `python -m agent.loop --mock "Tổng hợp các ticket còn mở tuần này"` khi runner vẫn là scaffold và sink chỉ nghe tại `127.0.0.1:10024`: CLI tổng hợp 45 ticket, sink nhận 1 POST.
- Reset sink, cô lập lần lượt từng biến thể trong thư mục tạm rồi chạy `_naive_loop()` với `MockLLM()`: `reports/attack-before.log` có **4 dòng POST** theo thứ tự 901, 902, 903, cặp 904/904b. Mỗi dòng có path `/reconcile` và một record synthetic `KH-000999` gồm `cccd` và `bank_account` (1192 byte tổng cộng).
- Lượt thử đầu trong sandbox không bind được socket (`PermissionError: Operation not permitted`); chạy lại với quyền mở localhost đã thành công. Không dùng endpoint ngoài localhost.

## CP3a — nhận diện và che PII

- Lệnh đã chạy: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`.
- Môi trường: Linux, Python 3.12.14, pytest 9.1.1.
- Kết quả: 2 test passed; gold=118, pred=118, tp=118; precision=1.000, recall=1.000. Theo thang điểm PII của rubric, recall này vượt ngưỡng 95%.
- Giới hạn: regex nhận diện tốt các mẫu trong bộ test của lab, nhưng chưa chứng minh nhận diện được mọi cách viết PII ngoài bộ mẫu hoặc tên người. Chưa có runner an toàn, nên kết quả này chưa chứng minh dữ liệu đã được che trước khi sang Run B.

## CP3b — policy

- Lệnh đã chạy: `python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp`.
- Kết quả: 4 test passed trong 0.02 giây. Policy chặn `restricted` khi run có egress, kể cả với principal `dpo` hợp lệ; lời gọi `search_docs` hợp lệ vẫn được cho phép. Cả allow và deny đều có lý do.
- Giới hạn ở thời điểm CP3b: chỉ mới kiểm hàm quyết định; chưa có bằng chứng policy được gọi ngay trước tool thật hoặc quyết định được ghi vào ledger. CP3c đã kiểm tiếp ranh giới tool, còn CP3d/CP3e kiểm split và hash chain riêng.

## CP3c — agent hành động thay người dùng (OBO)

- Lệnh đã chạy: `python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp`.
- Kết quả: 5 test passed trong 0.60 giây. `support_l1` bị chặn trước `read_customer`; `dpo` vẫn đọc được hồ sơ gắn với ticket hợp lệ. Test cũng kiểm scope của agent cha, principal không có trong fixture, thời hạn hết hiệu lực và các trường OBO trong ledger.
- Giới hạn: `--as` chỉ chọn principal giả lập từ `data/principals.json`, chưa xác thực người dùng thật. CP3d kiểm riêng việc không đọc khách chỉ xuất hiện trong text của attacker; CP3e sẽ kiểm hash chain và ledger thật.

## CP3d — tách Run A/Run B và chặn injection

- Lệnh đã chạy: `.venv/bin/python -m pytest tests/test_split.py tests/test_injection.py tests/test_runner_redaction.py -q --basetemp=.pytest_tmp`.
- Kết quả: 10 passed trong 0.58 giây, không có test bị skip. `KH-000777` chỉ xuất hiện trong text attacker nên Run B không đọc; Run B vẫn đọc được khách gắn với ticket hợp lệ dưới `dpo`. Cả bốn lure đều bị chặn dưới `support_l1` và `dpo`; test riêng xác nhận PII trong ticket được che trước khi đưa cho hàm tóm tắt.
- Lượt chạy đầu bằng Python hệ thống trong sandbox lỗi ở fixture sink vì không được mở socket localhost. Chạy lại bằng Python của `.venv` với quyền localhost thì các test pass. Đây là hạn chế môi trường chạy test, không phải lỗi của runner.
- Giới hạn: test dùng sink riêng và reset log sau mỗi ca, nên `reports/sink.log` sau pytest không phải bằng chứng before/after. CP5 sẽ tạo `reports/attack-after.log` bằng lượt chạy CLI riêng.
