# DPIA-lite — mô phỏng Day 24 L3

## Dữ liệu, mục đích và principal

`corpus/` chứa ticket Markdown **untrusted**, phân loại internal; `data/customers.json` chứa hồ sơ **synthetic restricted**: customer ID, tên, CCCD, điện thoại, STK, email và `related_tickets`.
`data/principals.json` là cấu hình quyền tin cậy trong lab. Không thu thập PII hoặc credential thật.

Mục đích Run A là `summarize-tickets`. Run B là `support-reply`: support_l1 được tìm ticket nhưng không đọc khách hàng; DPO được đọc khách gắn với ticket hợp lệ.
Quyền là giao của principal, scope của run và scope của parent; parent cấp search/read cho hai run con, Run A chỉ có search, Run B chỉ có read. Mỗi lần gọi kiểm lại TTL UTC 5 phút và ghi quyết định trước tool.

## Luồng xử lý và nơi dữ liệu đi

1. Người dùng gửi query tới `handle()`, chọn principal giả lập bằng `--as`.
2. Run A gọi `search_docs` sau policy allow; nhận diện chỉ thị để audit, redact CCCD/SĐT/STK/email trước summarize, và redact câu trả lời. Tên người nằm ngoài bốn recognizer của lab.
3. Run B chỉ nhận tuple số ticket lấy từ tên file (`ticket-904b.md` cũng ánh xạ 904). Không nhận text, customer ID, URL hoặc chỉ thị từ tài liệu.
4. Policy `read_customer` kiểm trước khi mở private fixture để dựng routing; support không tải store. DPO tra `related_tickets`, rồi kiểm lại policy ngay trước từng tool read. Toàn bộ dữ liệu riêng giữ trong Run B, không đưa sang LLM hoặc câu trả lời.
5. Khi phát hiện ý định gửi trong nội dung untrusted, dispatcher ghi `http_post` deny theo rule restricted+egress với đích cố định localhost. Không thực thi network tool sau deny. Detector bỏ sót cũng không cấp network scope cho Run B.
6. Ledger chỉ lưu metadata, TTL, principal hợp lệ, reason và SHA-256 của args; principal lạ lưu dưới hash. `reports/attack-before.log` cố ý giữ PII synthetic để chứng minh baseline; log sau là 0 byte.

Endpoint lab duy nhất của `http_post` là `http://127.0.0.1:10024/reconcile`; allowlist gốc giữ nguyên. Chế độ chấm `--mock` không gọi LLM API hay cloud.

## Rủi ro và bằng chứng kiểm soát

| Rủi ro | Biện pháp / bằng chứng |
|---|---|
| Prompt injection dẫn agent đọc ID trong text | Run B dùng routing tin cậy; `tests/test_split.py` chứng minh KH-000777 không bị đọc, khách hợp lệ vẫn được đọc |
| Người dùng/agent con vượt quyền | PEP kiểm principal/purpose/scopes/TTL tại tool; `tests/test_obo.py` gồm cả allow và deny |
| PII xuất ra sink | 8 replay sau có sink rỗng; `reports/ledger.jsonl` có restricted `http_post` deny; `reports/evidence-check.json` đối chiếu dữ liệu |
| PII vào context/log | Redact bốn định dạng và không ghi args thô; `tests/test_runner_boundary.py`, test PII precision=recall=1.000 trên 120 mẫu |
| Sửa ledger | SHA-256 + prev_hash; `tests/test_ledger.py` và sửa một ký tự reason dòng giữa trong bản tạm khiến verify=False |
| Secret trong Git/dependency bị đổi | Gitleaks pin 8.30.1, hook, hash lock; `reports/secrets-incident.md` và log thật |

## Giới hạn và xử lý khi chuyển sang production

Đây là đánh giá kỹ thuật rút gọn, không phải hồ sơ DPIA pháp lý hoàn chỉnh hoặc bằng chứng tuân thủ toàn bộ luật.
`--as` không xác thực danh tính thật; routing DPO tải toàn bộ fixture để tra liên kết, chưa phải truy vấn database giới hạn từng record.
Các run tách theo hàm, identity và capability trong cùng process, chưa cách ly OS/container; LLM mock deterministic không đại diện mọi hành vi model thật.
Chế độ model thật tùy chọn trong scaffold có kết nối API riêng ngoài PEP này; chỉ kết quả `--mock` được bảo đảm và chấm trong lab.
Regex không xác thực số có thật, chưa phát hiện PERSON hay mọi STK không nhãn; hash args chưa phải anonymization nếu miền giá trị nhỏ.
Ledger không có mốc ngoài file nên không phát hiện cắt đuôi hoặc viết lại cả chuỗi; khóa chỉ bảo vệ trong cùng process.

Evidence được giữ trong repo để TA kiểm tra; không nộp sink.log làm việc hoặc môi trường .venv. Thời hạn lưu, xóa/cascade, xác thực, kiểm soát record, mã hóa, consent/cơ sở xử lý, hồ sơ pháp lý và quy trình thông báo sự cố phải được thiết kế riêng nếu dùng dữ liệu thật.
