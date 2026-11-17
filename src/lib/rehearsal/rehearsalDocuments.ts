/**
 * src/lib/rehearsal/rehearsalDocuments.ts
 * ───────────────────────────────────────
 * Jury Rehearsal Benchmark Dataset & Answer Keys.
 *
 * 5 synthetic unknown-style documents created strictly WITHOUT tuning
 * detectors to them, representing realistic enterprise diversity:
 * 1. Indic Hindi/English Mixed Loan Agreement
 * 2. Enterprise Procurement & Vendor Tax CSV
 * 3. DevOps Cloud Infrastructure Secrets & Config JSON
 * 4. Corporate HR Workplace Grievance Memo
 * 5. Clean Data Governance Whitepaper (Zero PII Baseline)
 */

export interface GroundTruthEntity {
  type: string;
  expectedValue: string;
  scope: 'DPDP personal data' | 'security/enterprise';
}

export interface RehearsalDocument {
  id: string;
  fileName: string;
  title: string;
  description: string;
  mimeType: string;
  rawText: string;
  answerKey: GroundTruthEntity[];
}

export const REHEARSAL_DOCUMENTS: RehearsalDocument[] = [
  // ── Document 1: Hindi/English Mixed Loan Agreement ─────────────────────────
  {
    id: 'REHEARSAL-DOC-01',
    fileName: 'Indic_Mixed_Loan_Agreement.txt',
    title: 'Bilingual Loan Facility Agreement (Hindi + English)',
    description: 'Bilingual retail credit sanction containing Indic borrower cues, PAN, Aadhaar, and salary notes.',
    mimeType: 'text/plain',
    rawText: `द्विभाषी ऋण अनुबंध / BILATERAL LOAN FACILITY AGREEMENT
दस्तावेज़ संख्या / Document Ref: IND-BNK-2026-771
शाखा / Branch: Connaught Place, New Delhi

उधारकर्ता विवरण / BORROWER DETAILS:
उधारकर्ता का नाम / Borrower: Vikram Malhotra
पहचान पत्र / Identity Type: भारतीय विशिष्ट पहचान प्राधिकरण (UIDAI)
आधार संख्या / Aadhaar Number: 4567 8901 2345
स्थायी खाता संख्या / Income Tax PAN: ABCPE5678K
पंजीकृत मोबाइल / Registered Mobile: +91 9823456789
आधिकारिक ईमेल / Email: vikram.m@delhitech.co.in

वित्तीय मूल्यांकन / FINANCIAL APPRAISAL:
मासिक वेतन / Monthly Net Remittance: INR 1,25,000
वेतन खाता / Remittance Account: 102938475612 (State Bank of India)
मंजूर ऋण राशि / Sanctioned Amount: INR 35,00,000

नियम व शर्तें / TERMS:
The borrower agrees that credit telemetry data is processed under DPDP Act 2023 safeguards.`,
    answerKey: [
      { type: 'NAME', expectedValue: 'Vikram Malhotra', scope: 'DPDP personal data' },
      { type: 'AADHAAR', expectedValue: '4567 8901 2345', scope: 'DPDP personal data' },
      { type: 'PAN', expectedValue: 'ABCPE5678K', scope: 'DPDP personal data' },
      { type: 'PHONE', expectedValue: '+91 9823456789', scope: 'DPDP personal data' },
      { type: 'EMAIL', expectedValue: 'vikram.m@delhitech.co.in', scope: 'DPDP personal data' },
      { type: 'FINANCIAL', expectedValue: 'INR 1,25,000', scope: 'DPDP personal data' },
      { type: 'BANK_ACCOUNT', expectedValue: '102938475612', scope: 'DPDP personal data' },
      { type: 'FINANCIAL', expectedValue: 'INR 35,00,000', scope: 'DPDP personal data' },
    ],
  },

  // ── Document 2: Enterprise Procurement & Vendor Tax CSV ────────────────────
  {
    id: 'REHEARSAL-DOC-02',
    fileName: 'Enterprise_Procurement_Ledger.csv',
    title: 'Multi-Vendor Settlement & GSTIN Ledger (CSV)',
    description: 'Structured procurement records with director signatures, GSTIN, and settlement accounts.',
    mimeType: 'text/csv',
    rawText: `VendorCode,CompanyLegalName,DirectorName,GSTIN,TaxPan,RemittanceAcct,ContactEmail
VEND-DEL-101,Apex Infra Logistics LLP,Rajesh Singhania,27AAACB1234P1Z2,AAACB1234P,98765432101234,r.singh@apexinfra.in
VEND-MAH-202,Kalyan Energy Systems,Meera Kulkarni,27BCDEF5678G2Z1,BCDEF5678G,50100456789012,m.kulkarni@kalyanenergy.com
VEND-KAR-303,Deccan Precision Tools,Sunil Hegde,29CDEFG9012H3Z5,CDEFG9012H,33445566778899,s.hegde@deccantools.in`,
    answerKey: [
      { type: 'NAME', expectedValue: 'Rajesh Singhania', scope: 'DPDP personal data' },
      { type: 'GSTIN', expectedValue: '27AAACB1234P1Z2', scope: 'security/enterprise' },
      { type: 'PAN', expectedValue: 'AAACB1234P', scope: 'DPDP personal data' },
      { type: 'BANK_ACCOUNT', expectedValue: '98765432101234', scope: 'DPDP personal data' },
      { type: 'EMAIL', expectedValue: 'r.singh@apexinfra.in', scope: 'DPDP personal data' },
      { type: 'NAME', expectedValue: 'Meera Kulkarni', scope: 'DPDP personal data' },
      { type: 'GSTIN', expectedValue: '27BCDEF5678G2Z1', scope: 'security/enterprise' },
      { type: 'PAN', expectedValue: 'BCDEF5678G', scope: 'DPDP personal data' },
      { type: 'BANK_ACCOUNT', expectedValue: '50100456789012', scope: 'DPDP personal data' },
      { type: 'EMAIL', expectedValue: 'm.kulkarni@kalyanenergy.com', scope: 'DPDP personal data' },
      { type: 'NAME', expectedValue: 'Sunil Hegde', scope: 'DPDP personal data' },
      { type: 'GSTIN', expectedValue: '29CDEFG9012H3Z5', scope: 'security/enterprise' },
      { type: 'PAN', expectedValue: 'CDEFG9012H', scope: 'DPDP personal data' },
      { type: 'BANK_ACCOUNT', expectedValue: '33445566778899', scope: 'DPDP personal data' },
      { type: 'EMAIL', expectedValue: 's.hegde@deccantools.in', scope: 'DPDP personal data' },
    ],
  },

  // ── Document 3: DevOps Cloud Infrastructure Secrets JSON ───────────────────
  {
    id: 'REHEARSAL-DOC-03',
    fileName: 'Production_Cluster_Credentials.json',
    title: 'Cloud Cluster Deployment Manifest with Hardcoded Secrets',
    description: 'Structured Kubernetes & AWS deployment config containing plain AWS keys, tokens, and passwords.',
    mimeType: 'application/json',
    rawText: `{
  "environment": "production-mumbai-ap-south-1",
  "deployment_target": "eks-cluster-core-privacy",
  "cloud_credentials": {
    "provider": "AWS",
    "access_key": "AKIAIOSFODNN7EXAMPLE",
    "client_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "api_key": "ghp_1234567890abcdefghijklmnopqrstuv1234"
  },
  "database": {
    "host": "aurora-db.internal.enterprise.in",
    "port": 5432,
    "user": "vault_admin",
    "password": "SuperSecretProductionPassword2026!"
  },
  "escalation_contact": {
    "lead_engineer": "Arjun Nambiar",
    "email": "arjun.nambiar@cloudcore.io",
    "emergency_phone": "+91 9741234567"
  }
}`,
    answerKey: [
      { type: 'SECRET_KEY', expectedValue: 'AKIAIOSFODNN7EXAMPLE', scope: 'security/enterprise' },
      { type: 'SECRET_KEY', expectedValue: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', scope: 'security/enterprise' },
      { type: 'SECRET_KEY', expectedValue: 'ghp_1234567890abcdefghijklmnopqrstuv1234', scope: 'security/enterprise' },
      { type: 'SECRET_KEY', expectedValue: 'SuperSecretProductionPassword2026!', scope: 'security/enterprise' },
      { type: 'NAME', expectedValue: 'Arjun Nambiar', scope: 'DPDP personal data' },
      { type: 'EMAIL', expectedValue: 'arjun.nambiar@cloudcore.io', scope: 'DPDP personal data' },
      { type: 'PHONE', expectedValue: '+91 9741234567', scope: 'DPDP personal data' },
    ],
  },

  // ── Document 4: Corporate HR Workplace Grievance Memo ──────────────────────
  {
    id: 'REHEARSAL-DOC-04',
    fileName: 'Internal_Grievance_Redressal_Memo.txt',
    title: 'Workplace Incident & Data Protection Grievance Memo',
    description: 'Internal memo detailing employee grievance under Section 13 with voter card, mobile, and income.',
    mimeType: 'text/plain',
    rawText: `CONFIDENTIAL INTERNAL MEMORANDUM // PRIVILEGED
TO: Data Protection Officer, PrivaGuard Compliance Cell
FROM: Employee Grievance Redressal Committee
DATE: 2026-11-12

SUBJECT: STATUTORY GRIEVANCE UNDER DPDP ACT 2023 (SECTION 13)

EMPLOYEE DETAILS:
Complainant Name: Rohan Deshmukh
Employee ID: EMP-BLR-841
Electoral Photo ID (Voter ID): BCD3847291
Personal Mobile: +91 9834567890
Personal Email: rohan.deshmukh@gmail.com
Current Monthly CTC: INR 92,000

STATEMENT OF GRIEVANCE:
Employee Rohan Deshmukh reports that internal HR payroll databases retained unmasked biometric Aadhaar references after contract completion. The employee has formally exercised the statutory Right to Erasure under Section 12.

Consulting HR Director: Anita Sen
Designated DPO: dpo-officer@enterprise.in`,
    answerKey: [
      { type: 'NAME', expectedValue: 'Rohan Deshmukh', scope: 'DPDP personal data' },
      { type: 'VOTER_ID', expectedValue: 'BCD3847291', scope: 'DPDP personal data' },
      { type: 'PHONE', expectedValue: '+91 9834567890', scope: 'DPDP personal data' },
      { type: 'EMAIL', expectedValue: 'rohan.deshmukh@gmail.com', scope: 'DPDP personal data' },
      { type: 'FINANCIAL', expectedValue: 'INR 92,000', scope: 'DPDP personal data' },
      { type: 'NAME', expectedValue: 'Anita Sen', scope: 'DPDP personal data' },
      { type: 'EMAIL', expectedValue: 'dpo-officer@enterprise.in', scope: 'DPDP personal data' },
    ],
  },

  // ── Document 5: Clean Architecture Whitepaper (Zero PII Baseline) ──────────
  {
    id: 'REHEARSAL-DOC-05',
    fileName: 'Zero_Knowledge_Architecture_Whitepaper.txt',
    title: 'Statutory Architecture Whitepaper (Zero-PII Baseline)',
    description: 'Technical whitepaper explaining DPDP cryptographic isolation with ZERO sensitive personal identifiers.',
    mimeType: 'text/plain',
    rawText: `ENTERPRISE DATA PRIVACY IN THE FOUNDATION LLM ERA
A Whitepaper on Sovereign Cryptographic Enclaves & DPDP Compliance

EXECUTIVE SUMMARY:
Modern enterprise architectures require decoupling language model cognition from raw data persistence.
Section 8 of the Digital Personal Data Protection Act (DPDP) 2023 imposes affirmative obligations
on Data Fiduciaries to maintain technical safeguards against accidental data exfiltration.

ARCHITECTURAL PRINCIPLES:
1. In-Memory Ephemeral Masking:
Transforming identifiable tokens into deterministic semantic placeholders prior to network dispatch.
Original identifiers remain in client-controlled memory barriers with strict 10-minute maximum horizons.

2. Independent Dual-Pass Verification:
Before any outbound transmission occurs, an orthogonal validator performs structural heuristic analysis.
If residual tokens are detected, the gateway automatically executes an immediate fail-closed circuit trip.

3. Complete Auditability:
Every de-identification produces an immutable compliance manifest tracking regulatory sections,
token maps, and verification timestamps without recording raw personal values.

CONCLUSION:
By operating at the network perimeter, enterprise AI firewalls enable foundation model integration
while providing verifiable statutory compliance.`,
    answerKey: [], // STRICT ZERO PII EXPECTED
  },
];
