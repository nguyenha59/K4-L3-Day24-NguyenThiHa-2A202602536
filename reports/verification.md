# Verification — Day 24 L3

Ngày thực hiện: **12/10/2026 (Asia/Bangkok)**. Đọc toàn bộ README, RULES, CHECKPOINTS, RUBRIC và SUBMISSION trước khi làm.
Môi trường: Windows native / PowerShell, Python **3.11.8**, Gitleaks **8.30.1**; dependency cài trong `.venv` theo hash lock.
WSL không dùng được (`Wsl/EnumerateDistros/Service/E_ACCESSDENIED`); README chưa pilot Windows native, nên kết quả dưới đây là kiểm thử thực trên Windows.

| Kiểm tra | Kết quả và bằng chứng |
|---|---|
| `python -m pytest tests/ -q` | **36 passed**, không FAIL/SKIP; `reports/pytest.log` (33 test gốc + 3 test bổ sung boundary). Không sửa test bắt buộc |
| `python -m pytest tests/test_pii.py -s` | 120 mẫu, gold=118, pred=118, TP=118, **precision=1.000, recall=1.000**; `reports/pii-metrics.log` |
| `python -m agent.check_lure corpus/ticket-90*.md` | **4/4 lure sẵn sàng**; `reports/check-lure.log` |
| Baseline trước triển khai | `reports/attack-before.log:1` có đúng hồ sơ synthetic KH-000999; 4/4 replay độc lập rò rỉ trong `reports/replay-before.json` |
| Replay sau pytest/reset, cùng query, principal DPO | `reports/attack-after.log` **0 byte**; 8/8 replay support/DPO có sink rỗng, ledger hợp lệ trong `reports/replay-after.json` |
| `python scripts/verify_lab.py` | Kiểm 20 artifact bắt buộc, baseline trùng fixture, 8 ledger replay, không PII thô trong ledger; `reports/evidence-check.json` |
| Ledger | `verify(Path('reports/ledger.jsonl')) == True`, mọi dòng có reason/OBO/run_id/expires_at; deny http_post ở dòng 25 và 50 |
| Tamper proof | Thêm một ký tự vào reason của dòng giữa trong **bản sao tạm**, verify=False; số dòng và kết quả trong `reports/evidence-check.json`; không phá ledger nộp |
| Dependency | `piptools compile --generate-hashes` và `pip install --require-hashes --force-reinstall` exit 0; `reports/supply-chain-compile.log`, `reports/supply-chain-install.log` |
| Scanner lịch sử | 1 finding synthetic, rule `lab24-synthetic-token`, commit `1bdd849`, giá trị REDACTED; exit 1 mong đợi; `reports/supply-chain-history.json` |
| Scanner bài nộp hiện tại | Snapshot toàn bộ source/evidence, không environment/cache: không finding, exit 0; `reports/supply-chain-current-submission.log` |
| `pre-commit run --all-files` | Gitleaks hook pin v8.30.1 **Passed**; `reports/supply-chain-hook.log`. Hook đã cài, không dùng --no-verify |
| Hook thực sự chặn secret | Repo tạm stage token giả: hook deny exit 1, rule đúng, REDACTED; `reports/supply-chain-hook-probe.log` |
| Pháp lý | Mapping điều khoản đã đối chiếu nguồn Công báo/OWASP chính thức; `reports/compliance-mapping.md`. DPIA-lite ghi rõ giới hạn mô phỏng |

## Các vấn đề gặp và cách giải quyết

- Lần chạy suite khi incident note còn là template: 32 passed, 1 failed ở `test_incident_note_identifies_synthetic_leak`. Hoàn thiện note bằng kết quả scanner thật, chạy lại suite cuối: 36 passed.
- Sandbox chặn tải package/GitHub và đặt PIP_NO_INDEX; tải từ public PyPI/release chính thức với quyền network được chấp thuận, cài isolated theo hash. Không dùng secret thật.
- Lệnh Gitleaks quét toàn workspace có false positive ở `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py:45` (alias RegEnumKey), exit 1; giữ log `reports/supply-chain-current.log`. Giải quyết bằng quét snapshot artifact bài nộp, không sửa rule/allowlist để che source.
- Pre-commit cache mặc định nằm ngoài workspace; đặt `PRE_COMMIT_HOME` vào `.tools/pre-commit-cache` khi kiểm. Git status dùng `--no-optional-locks` để tránh ghi refresh index trong sandbox chỉ đọc Git.
- Không còn lỗi chức năng trong phạm vi mock/test của lab. Bonus tùy chọn không triển khai. Các giới hạn production (fixture auth, regex/PERSON, cùng process, hash-chain không có anchor ngoài) ghi trong DPIA-lite.

## Tái kiểm trên máy hiện tại

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONIOENCODING = 'utf-8'
$env:PRE_COMMIT_HOME = Join-Path (Get-Location) '.tools\pre-commit-cache'
python -m pytest tests/ -q
python -m agent.check_lure corpus/ticket-90*.md
python scripts/verify_lab.py
python scripts/verify_supply_chain.py versions
python scripts/verify_supply_chain.py current-submission
python scripts/verify_supply_chain.py hook
git --no-optional-locks status --short
```

`scripts/replay_lab.py after` có thể chạy lại để tái tạo log sau; `before` chỉ chạy khi runner còn scaffold và từ chối chạy trên runner đã contain.
Log working `reports/sink.log`, `.venv/`, `.tools/`, `.cache/` không thuộc bài nộp. Các attack log và ledger bắt buộc được stage riêng bằng `git add -f` theo SUBMISSION.
Giữ nguyên đầy đủ lịch sử chứa token giả. SHA bản gốc: `52b33b5bddfcfdb5425010d6996c5c1d8eed13bd`; SHA commit bài làm cuối xác định bằng `git log -1 --format=%H` sau khi commit (không dùng SHA bản gốc thay SHA bài làm).
Deadline/nơi nộp theo thông báo key coach/TA; repository không cung cấp thông tin này.
