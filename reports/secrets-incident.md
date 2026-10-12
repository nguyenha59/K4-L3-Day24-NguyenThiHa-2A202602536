# Secret giả trong lịch sử Git

Ngày thực hiện: 12/10/2026 (Asia/Bangkok). Chỉ dùng dữ liệu tổng hợp của lab; token cài sẵn là vô hiệu. Không tạo hay dùng credential thật.

## Phát hiện và bằng chứng

- Scanner: **Gitleaks 8.30.1**, xác nhận bằng lệnh `gitleaks version` trong [supply-chain-versions.log](supply-chain-versions.log).
- Binary Windows x64 lấy từ [release chính thức v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1), do WSL trả lỗi `Wsl/EnumerateDistros/Service/E_ACCESSDENIED`. SHA-256 của `gitleaks_8.30.1_windows_x64.zip` trùng file checksum chính thức: `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`; xem [supply-chain-download.log](supply-chain-download.log). Windows native chưa được pilot theo README; đây là kết quả thực chạy trên môi trường này.
- Quét lịch sử: `gitleaks git --config .gitleaks.toml --redact --no-color --verbose .` tìm **đúng 1 finding** của rule `lab24-synthetic-token`, file `lab-fake-secret.txt`, dòng 1, commit **`1bdd849922156c868a5ee9293d68f5b72e242d2c`** (`1bdd849`). Exit code **1 là kết quả mong đợi**; không diễn giải thành sự cố credential thật. Xem [supply-chain-history.log](supply-chain-history.log) và [JSON đã redact](supply-chain-history.json).
- Giá trị token không được chép vào báo cáo; `Match` và `Secret` của JSON đều là `REDACTED`.

## File hiện tại và phạm vi quét

Lệnh nguyên trạng `gitleaks dir --config .gitleaks.toml --redact --verbose .` còn quét cả dependency đã cài trong `.venv`. Nó trả exit 1 vì `generic-api-key` ở `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py:45`: alias hàm Windows registry `RegEnumKey`, không phải credential của bài làm. Giữ nguyên kết quả trong [supply-chain-current.log](supply-chain-current.log), không xóa hay sửa bằng chứng này.

Để kiểm đúng **file bài nộp hiện tại**, tạo snapshot tạm của `git ls-files --cached --others --exclude-standard`, thêm các evidence bắt buộc bị `.gitignore` chặn (`attack-before.log`, `attack-after.log`, `ledger.jsonl` nếu tồn tại), rồi chạy cùng `gitleaks dir --config .gitleaks.toml --redact --no-color --verbose .` trong snapshot. Danh sách file và cwd thực có trong [supply-chain-current-submission.log](supply-chain-current-submission.log): **không finding, exit 0**. Chỉ loại thư mục môi trường/cache sinh ra, không thay `.gitleaks.toml`, không thêm allowlist/fingerprint để làm sạch source hay evidence.

## Hook và dependency

[.pre-commit-config.yaml](../.pre-commit-config.yaml) dùng repo chính thức `https://github.com/gitleaks/gitleaks`, `rev: v8.30.1`, hook `gitleaks-system`, `pass_filenames: false`, giữ `.gitleaks.toml` của đề. [Hook chính thức](https://github.com/gitleaks/gitleaks/blob/v8.30.1/.pre-commit-hooks.yaml) chạy `gitleaks git --pre-commit --redact --staged --verbose`; vì vậy `pre-commit run --all-files` vẫn kiểm nội dung staged của Git, không thay thế lần quét lịch sử hoặc snapshot ở trên. Gitleaks đã ở PATH khi kiểm; xem [supply-chain-hook.log](supply-chain-hook.log). Git hook đã cài bằng `pre-commit install`, xem [supply-chain-hook-install.log](supply-chain-hook-install.log).

Kiểm thử hook độc lập trong repo Git tạm: chỉ stage config và một token giả `LAB24-DEMO`, chạy `pre-commit run --all-files`, hook thực sự **deny** với exit 1 và rule `lab24-synthetic-token`, giá trị vẫn `REDACTED`; xem [supply-chain-hook-probe.log](supply-chain-hook-probe.log). Không tạo commit, không thay index của repo bài nộp, repo tạm đã được dọn. `python -m pytest tests/test_supply_chain.py -q`: **3 passed**.

[requirements.lock](../requirements.lock) sinh thật bằng `python -m piptools compile --generate-hashes -o requirements.lock requirements.txt` (Python 3.11, pip-tools 7.6.2), pin 11 package và SHA-256 cho từng package. Xem [supply-chain-compile.log](supply-chain-compile.log). Sau đó **cài lại** toàn bộ dependency bằng `python -m pip --isolated install --index-url https://pypi.org/simple --require-hashes --force-reinstall -r requirements.lock`, exit 0; xem [supply-chain-install.log](supply-chain-install.log). `--isolated` cần vì môi trường sandbox mặc định đặt `PIP_NO_INDEX`; lần tải ban đầu trong sandbox thất bại, lần chạy với quyền network và public PyPI thành công. Không đưa proxy hay credential vào log.

## Nếu credential bị lộ là thật

Phải **thu hồi/rotate** tại nhà cung cấp ngay, vô hiệu hóa credential cũ, kiểm log sử dụng trái phép và rà soát phạm vi lộ. Cấp credential mới với quyền tối thiểu, cập nhật nơi sử dụng và xác minh credential cũ đã bị từ chối. Sau đó mới xử lý bản sao trong file/lịch sử/cache theo quy trình phối hợp và tiếp tục quét.

Xóa file khỏi HEAD không thu hồi quyền dùng credential: người đã lấy token từ lịch sử hoặc bản sao vẫn dùng được nếu nhà cung cấp chưa vô hiệu hóa. Pin dependency, hash package và pin hook giúp kiểm soát artifact/phát hiện secret mới; chúng không rotate credential và không chứng minh package không có lỗ hổng. `gitleaks-system` còn phụ thuộc binary thật trong PATH nên đã kiểm cả phiên bản lẫn checksum ở trên. Không sửa lịch sử Git để che token tổng hợp phục vụ checkpoint.
