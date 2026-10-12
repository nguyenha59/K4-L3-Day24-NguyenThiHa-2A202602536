# Baseline — checkpoint 1

1. `_naive_loop()` tại `agent/loop.py:27` chưa tạo identity, `run_id`, scopes hay TTL riêng; `run_once()` tại `agent/loop.py:57` chỉ chọn principal mô phỏng và scaffold chuyển về baseline, nên baseline không thực thi OBO.
2. Chính `_naive_loop()` tin chỉ thị trong kết quả `search_docs`, lấy `customer_ids` từ free text, gọi `read_customer` rồi `http_post` mà không qua policy/ledger; allowlist tại `agent/tools.py:68` chỉ giới hạn đích localhost, không cấp quyền gửi hồ sơ khách hàng.
3. `make_handler()` tại `sink/sink.py:40` ghi body POST vào `reports/sink.log`; bản sao `reports/attack-before.log:1` chứa nguyên hồ sơ giả `KH-000999`, gồm CCCD/SĐT/STK/email trùng `data/customers.json`, còn `reports/replay-before.json` chứng minh cả 4 biến thể độc lập đều rò rỉ.
