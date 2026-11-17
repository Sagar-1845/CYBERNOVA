# ZEROLEAK AI - test pack

All data is synthetic. Aadhaar numbers pass Verhoeff, cards pass Luhn, GSTIN passes its checksum.
Each file in `inputs/` has an answer key in `keys/` (expected sensitive values with a location, plus `must_not_flag` traps).

## Files and what they test
| File | Operation tested | Expected |
|---|---|---|
| 01_unstructured_loan_email.txt | Unstructured text, all entity types, traps | See key: T1 22, T2 21, traps 10 |
| 02_salary_sheet.csv | CSV cells, header-as-context | Every value in Name/Email/Phone/Aadhaar/PAN/Salary/Bank/IFSC/EmpID columns; Notes traps not flagged |
| 03_hr_records.xlsx | Multi-sheet, hidden sheet, cell comment, document properties | Hidden-sheet Aadhaar and password, comment PAN, and author names (metadata) reported |
| 04_api_config_nested.json | Nested JSON secrets and PII by path | 5 secrets by key name; metrics/version numbers untouched |
| 05_customer_feed.xml | XML attributes and nested elements | `pan` attribute, names, phones, addresses; ids and ticket numbers untouched |
| 06_kyc_form.docx | DOCX table, header, footer, core properties | Header/footer values and author names found; metadata flagged |
| 07_digital_report.pdf | Digital PDF, 2 pages, PDF Author metadata | 14 entities; page numbers correct |
| 08_scanned_kyc.pdf, 08b_id_card.png | OCR (image-only) | 12 of 13 values read exactly by tesseract on the build machine; see caveat |
| 09_clean_document.txt | Clean document | 0 detections, Safe |
| 10_misleading_numbers.txt | False-positive traps | 0 detections |
| negative/ | Errors and robustness | See table below |
| seed/audit_seed_events.json | Audit log, analytics, filters | Expected dashboard numbers at the bottom of the file |
| seed/policy_*.json | Policy import/validation (adapt to your schema) | valid imports; weak-credential profile rejected; malformed rejected |

## negative/
| File | Expected |
|---|---|
| n01_empty.txt | Rejected: empty file |
| n02_corrupt.pdf | Rejected: corrupt PDF |
| n03_not_really_a_pdf.pdf | Rejected: content does not match extension |
| n04_encrypted.pdf (password test123) | Rejected: encrypted |
| n05_malformed.json | Rejected: invalid JSON |
| n06_xxe.xml | Rejected: external entity |
| n07_injection_and_script.txt | Script tags inert; injection flagged; name and PAN still masked |
| n08_large_text.txt (~2 MB) | Responsive UI; 4 planted values masked (start, middle, end) |
| README_oversize.txt | How to create an over-limit file and an unsafe filename |

## Database / operations checklist (adapt to your storage)
1. CREATE: process each input file; one audit record per processing, created once, with the fields in the seed file.
2. READ: list, sort by time, filter by policy / risk band / verification result / failure, paginate; open a record.
3. UPDATE: status moves Queued -> Extracting -> Ready -> Masked -> Verified (or Failed); re-running a file does not duplicate or corrupt earlier records.
4. DELETE: remove a document: extracted text, tokens and vault entries are cleared; the audit record stays without content.
5. INTEGRITY: if audit rows carry HMAC signatures, change one stored field by hand: signature verification must fail and show it.
6. ANALYTICS: after loading the seed set, dashboard numbers must equal `expected_dashboard_numbers`; recompute after a new run.
7. PERSISTENCE: reload the page / restart the backend: audit history behaves as designed (persists or clears) and nothing raw is left in storage or logs.
8. CONCURRENCY: upload 5 files at once: five separate records, no mixed-up tokens.
9. PRIVACY: search all logs, storage and network traffic for any original value from the keys: zero hits.
10. RETENTION: after the retention period, temp data is deleted.

## Known limits of this pack
- OCR caveat: on the build machine, tesseract read IFSC `ZLBK0001206` as `ZLBKO001206` (letter O instead of zero). A good detector normalises this; a miss here is a real finding.
- No Hindi in the PDF/PNG (no Devanagari font on the build machine). Hindi is in file 01 only.
- No DOCX comments or tracked changes, no ZIP bomb, no password-protected DOCX. Create those yourself if needed.
- Seed events are a made-up schema based on your spec. Map the field names to your real tables.
