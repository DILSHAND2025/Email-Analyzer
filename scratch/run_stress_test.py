"""
Stress test corpus generator and pipeline evaluator for MAVERICK.
Generates 19 diverse, realistic .eml emails across 5 categories and executes
the complete forensic pipeline against each.
"""

import base64
import os
import shutil
import sys
from typing import Any, Dict, List

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath("."))

from maverick.reports import run_full_pipeline_and_generate_report

STRESS_DIR = os.path.join(os.path.dirname(__file__), "..", "samples", "stress_test")
os.makedirs(STRESS_DIR, exist_ok=True)

# PE Executable stub bytes
PE_STUB = bytearray(512)
PE_STUB[0:2] = b"MZ"
PE_STUB[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little")
PE_STUB[0x80:0x84] = b"PE\x00\x00"
PE_STUB[0x84:0x86] = (0x014C).to_bytes(2, byteorder="little")
PE_STUB[0x86:0x88] = (1).to_bytes(2, byteorder="little")
PE_STUB[0x94:0x96] = (0xE0).to_bytes(2, byteorder="little")
PE_STUB[0x96:0x98] = (0x0102).to_bytes(2, byteorder="little")
PE_STUB_B64 = base64.b64encode(bytes(PE_STUB)).decode("ascii")

# Minimal valid PDF bytes
PDF_BYTES = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n0000000102 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
PDF_B64 = base64.b64encode(PDF_BYTES).decode("ascii")

# Minimal valid PNG bytes
PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
PNG_B64 = base64.b64encode(PNG_BYTES).decode("ascii")

# EICAR standard anti-virus test signature
EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_B64 = base64.b64encode(EICAR_BYTES).decode("ascii")

# Load benign macro docx bytes from samples if present
MACRO_DOCX_PATH = os.path.join(os.path.dirname(__file__), "..", "samples", "sample_macro_benign.docx")
if os.path.exists(MACRO_DOCX_PATH):
    with open(MACRO_DOCX_PATH, "rb") as mf:
        MACRO_DOCX_B64 = base64.b64encode(mf.read()).decode("ascii")
else:
    MACRO_DOCX_B64 = ""


EMAILS_DEFINITIONS = [
    # -------------------------------------------------------------
    # Category 1: Clear phishing emails with malicious links
    # -------------------------------------------------------------
    {
        "filename": "phish_01_paypal_account_suspended.eml",
        "category": "Clear Phishing",
        "expected": "Critical",
        "content": f"""Return-Path: <bounce@attacker-server.com>
Received: from mx1.target.com (mx1.target.com [198.51.100.99])
    by mailserver.target.internal with ESMTPS id 4SfK1001;
    Sat, 19 Sep 2026 08:00:00 +0000
Authentication-Results: mx1.target.com; spf=fail; dkim=none; dmarc=fail;
From: "PayPal Security Dept" <service@paypal-security-update.xyz>
To: "Customer" <victim@target.com>
Subject: URGENT: Your PayPal Account Has Been Restricted - Action Required
Date: Sat, 19 Sep 2026 08:00:00 +0000
Message-ID: <phish-01-pp@paypal-security-update.xyz>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

URGENT NOTICE: Your PayPal account has been restricted due to suspicious unauthorized login attempts.
Click immediately to verify your identity and restore full access:
http://198.51.100.99/paypal/login.php

Failure to confirm your account credentials within 24 hours will result in permanent suspension and forfeiture of funds.
Claim your verification refund now.
""",
    },
    {
        "filename": "phish_02_microsoft365_password_expired.eml",
        "category": "Clear Phishing",
        "expected": "High",
        "content": f"""Return-Path: <nobody@evil-vps.net>
Received: from relay.evil-vps.net ([203.0.113.15])
    by mx1.target.com with ESMTP id 9ZzY2002;
    Sat, 19 Sep 2026 08:15:00 +0000
Authentication-Results: mx1.target.com; spf=softfail; dkim=none; dmarc=fail;
From: "IT Support Desk" <support@it-security-portal.top>
To: "Employee" <user@target.com>
Subject: Action Required: Your Microsoft 365 Password Expires Today
Date: Sat, 19 Sep 2026 08:15:00 +0000
Message-ID: <phish-02-ms@it-security-portal.top>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Your corporate Microsoft 365 password will expire in 2 hours.
To keep your current password and prevent email disruption, click the link below to validate your credentials:
https://login.microsoft-password-reset.xyz/token=49102

Enter your current password and corporate username to verify authentication.
""",
    },
    {
        "filename": "phish_03_docusign_wire_fraud.eml",
        "category": "Clear Phishing",
        "expected": "High",
        "content": f"""Return-Path: <attacker@relay.click>
Received: from mx1.target.com (mx1.target.com [192.0.2.77])
    by mailserver.target.internal with ESMTPS id 4SfK3003;
    Sat, 19 Sep 2026 08:30:00 +0000
Authentication-Results: mx1.target.com; spf=fail; dkim=none; dmarc=fail;
From: "DocuSign Signature Service" <document@esign-docusign-review.xyz>
To: "Accounting Dept" <accounting@target.com>
Subject: URGENT: Wire Transfer Authorization Document Ready for Signature
Date: Sat, 19 Sep 2026 08:30:00 +0000
Message-ID: <phish-03-ds@esign-docusign-review.xyz>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

DocuSign: You have received a financial document for immediate electronic signature.
Review invoice and wire payment instructions:
https://docusign-financial-review.xyz/sign/invoice4891

Click immediately to confirm payment routing numbers and approve invoice transfer.
""",
    },
    {
        "filename": "phish_04_bank_alert_verify.eml",
        "category": "Clear Phishing",
        "expected": "High",
        "content": f"""Return-Path: <spammer@hacked-host.loan>
Received: from relay-bad.net ([198.51.100.200])
    by mx1.target.com with ESMTP id 8BbA4004;
    Sat, 19 Sep 2026 08:45:00 +0000
Authentication-Results: mx1.target.com; spf=fail; dkim=none; dmarc=fail;
From: "Bank Security Alert" <fraud-prevention@secure-chase-update.buzz>
To: "Account Holder" <victim@target.com>
Subject: Security Alert: Unauthorized Debit Attempt - Immediate Verification
Date: Sat, 19 Sep 2026 08:45:00 +0000
Message-ID: <phish-04-bk@secure-chase-update.buzz>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

We detected an unauthorized debit charge of $2,450.00 on your account.
If you did not authorize this charge, click immediately to dispute and reverse:
http://203.0.113.50/secure/bank.html

You must verify your card number, PIN, and SSN to reverse the transaction.
""",
    },

    # -------------------------------------------------------------
    # Category 2: Clean benign emails
    # -------------------------------------------------------------
    {
        "filename": "clean_01_enron_lunch_meeting.eml",
        "category": "Clean Benign",
        "expected": "Low",
        "content": """Return-Path: <vkaminski@enron.com>
Received: from mailserver.enron.com (mailserver.enron.com [198.51.100.10])
    by target.internal with ESMTPS id 1AaA5005;
    Sat, 19 Sep 2026 09:00:00 +0000
Authentication-Results: mx.target.com; spf=pass; dkim=pass header.d=enron.com; dmarc=pass;
From: "Vince Kaminski" <vkaminski@enron.com>
To: "Shirley Crenshaw" <shirley.crenshaw@enron.com>
Subject: Lunch meeting tomorrow to review budget research
Date: Sat, 19 Sep 2026 09:00:00 +0000
Message-ID: <clean-01-enron@enron.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Shirley,

Let's meet tomorrow at 12:30 for lunch in the cafeteria to review the quarterly risk modeling budget presentation.
I will bring the draft research slides.

Best regards,
Vince
""",
    },
    {
        "filename": "clean_02_corporate_all_hands_schedule.eml",
        "category": "Clean Benign",
        "expected": "Low",
        "content": """Return-Path: <announcements@corp-target.com>
Received: from mx1.corp-target.com (mx1.corp-target.com [198.51.100.11])
    by mailserver.corp-target.internal with ESMTPS id 2BbB6006;
    Sat, 19 Sep 2026 09:15:00 +0000
Authentication-Results: mx.target.com; spf=pass; dkim=pass header.d=corp-target.com; dmarc=pass;
From: "Internal Communications" <announcements@corp-target.com>
To: "All Employees" <all-staff@corp-target.com>
Subject: Reminder: Quarterly Company All-Hands Meeting This Thursday
Date: Sat, 19 Sep 2026 09:15:00 +0000
Message-ID: <clean-02-ah@corp-target.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello Team,

Please join us this Thursday at 2:00 PM EST for our quarterly company all-hands meeting.
Agenda items include:
- Product roadmap and engineering updates
- Financial performance and milestones
- Open Q&A session with executive leadership

We look forward to seeing everyone there.
""",
    },
    {
        "filename": "clean_03_engineering_standup_notes.eml",
        "category": "Clean Benign",
        "expected": "Low",
        "content": """Return-Path: <alex.rivera@tech-firm.com>
Received: from mail.tech-firm.com (mail.tech-firm.com [198.51.100.14])
    by target.internal with ESMTPS id 3CcC7007;
    Sat, 19 Sep 2026 09:30:00 +0000
Authentication-Results: mx.target.com; spf=pass; dkim=pass header.d=tech-firm.com; dmarc=pass;
From: "Alex Rivera" <alex.rivera@tech-firm.com>
To: "Backend Engineering Team" <backend-dev@tech-firm.com>
Subject: Daily Standup Summary & Sprint Progress
Date: Sat, 19 Sep 2026 09:30:00 +0000
Message-ID: <clean-03-su@tech-firm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi Team,

Here is our standup summary for this morning:
- Alex completed the Redis connection pool optimization for the API gateway.
- Priya is making great progress on the database schema migration scripts.
- The Kubernetes ingress routing issue was resolved yesterday afternoon.

Have a productive afternoon!
Alex
""",
    },
    {
        "filename": "clean_04_weekly_newsletter_digest.eml",
        "category": "Clean Benign",
        "expected": "Low",
        "content": """Return-Path: <bounces@pythonweekly.com>
Received: from mailer.pythonweekly.com (mailer.pythonweekly.com [198.51.100.16])
    by target.internal with ESMTPS id 4DdD8008;
    Sat, 19 Sep 2026 09:45:00 +0000
Authentication-Results: mx.target.com; spf=pass; dkim=pass header.d=pythonweekly.com; dmarc=pass;
From: "Python Weekly" <digest@pythonweekly.com>
To: "Subscriber" <dev@target.com>
Subject: Python Weekly - Issue 520: Modern Concurrency & Profiling
Date: Sat, 19 Sep 2026 09:45:00 +0000
Message-ID: <clean-04-pw@pythonweekly.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Welcome to issue #520 of Python Weekly.

In this issue:
- Deep dive into Python 3.14 benchmark improvements
- Architectural guide to asynchronous worker pools with asyncio
- Community spotlight: open-source scientific computing libraries

Happy coding,
Rahul Sharma
""",
    },

    # -------------------------------------------------------------
    # Category 3: SPF/DKIM/DMARC Failures with Benign Content
    # -------------------------------------------------------------
    {
        "filename": "auth_fail_01_misconfigured_newsletter.eml",
        "category": "Auth Failure / Benign Text",
        "expected": "Low",
        "content": """Return-Path: <bounces@external-blast-relay.net>
Received: from relay-unlisted.net ([198.51.100.80])
    by mx1.target.com with ESMTP id 5EeE9009;
    Sat, 19 Sep 2026 10:00:00 +0000
Authentication-Results: mx1.target.com; spf=softfail; dkim=none; dmarc=fail;
From: "Gardening Specials" <specials@gardening-world.com>
To: "Subscriber" <customer@target.com>
Subject: Autumn Gardening Tips: Planting Spring Bulbs
Date: Sat, 19 Sep 2026 10:00:00 +0000
Message-ID: <af-01-gw@gardening-world.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello Gardening Enthusiasts,

Autumn is the perfect time to plant tulip bulbs and enrich your garden soil with organic compost.
Remember to water thoroughly before the first freeze to ensure strong root development.

Enjoy your autumn garden,
The Gardening World Team
""",
    },
    {
        "filename": "auth_fail_02_forwarded_meeting_invite.eml",
        "category": "Auth Failure / Benign Text",
        "expected": "Low",
        "content": """Return-Path: <clark@university.edu>
Received: from listserv.external-partner.org ([198.51.100.85])
    by mx1.target.com with ESMTP id 6FfF1010;
    Sat, 19 Sep 2026 10:15:00 +0000
Authentication-Results: mx1.target.com; dkim=fail (body hash did not verify); spf=neutral; dmarc=fail;
From: "Prof. Arthur Clark" <clark@university.edu>
To: "Curriculum Committee" <faculty@target.com>
Subject: [Mailing-List] Updated Curriculum Committee Meeting Time
Date: Sat, 19 Sep 2026 10:15:00 +0000
Message-ID: <af-02-univ@university.edu>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

[Mailing-List-Notice]
Colleagues,

Please note that our upcoming curriculum committee meeting has been moved to this Friday at 3:00 PM in Hall B.
Please review the syllabus outline beforehand so we can finalize course credits.

Best regards,
Arthur Clark
""",
    },
    {
        "filename": "auth_fail_03_spoofed_from_benign_text.eml",
        "category": "Auth Failure / Benign Text",
        "expected": "Medium",
        "content": """Return-Path: <spoofer@cheap-vps-hosting.net>
Received: from rogue-relay.net ([198.51.100.111])
    by mx1.target.com with ESMTP id 7GgG2020;
    Sat, 19 Sep 2026 10:30:00 +0000
Authentication-Results: mx1.target.com; spf=fail; dkim=none; dmarc=fail;
From: "Presidential Office" <contact@whitehouse.gov>
To: "Citizen" <citizen@target.com>
Subject: Wishing you a pleasant holiday weekend
Date: Sat, 19 Sep 2026 10:30:00 +0000
Message-ID: <af-03-sp@whitehouse.gov>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Dear Citizen,

We wish you and your family a safe, peaceful, and pleasant holiday weekend ahead.

Warmest regards.
""",
    },

    # -------------------------------------------------------------
    # Category 4: Emails with attachments (clean vs malicious / EICAR)
    # -------------------------------------------------------------
    {
        "filename": "attachment_01_clean_pdf_report.eml",
        "category": "Attachment Forensics",
        "expected": "Low",
        "content": f"""Return-Path: <billing@reliable-partner.com>
Received: from mail.reliable-partner.com (mail.reliable-partner.com [198.51.100.22])
    by target.internal with ESMTPS id 8HhH3030;
    Sat, 19 Sep 2026 10:45:00 +0000
Authentication-Results: mx.target.com; spf=pass; dkim=pass header.d=reliable-partner.com; dmarc=pass;
From: "Finance Billing" <billing@reliable-partner.com>
To: "Client Accounts" <accounts@target.com>
Subject: Monthly Account Statement - September 2026
Date: Sat, 19 Sep 2026 10:45:00 +0000
Message-ID: <att-01-pdf@reliable-partner.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="===============BOUNDARY_PDF_01=="

--===============BOUNDARY_PDF_01==
Content-Type: text/plain; charset="utf-8"

Dear Customer,

Please find attached your monthly account statement for the billing period ending September 2026.
Should you have any questions regarding your invoice, please contact our accounts team.

Thank you for your business.

--===============BOUNDARY_PDF_01==
Content-Type: application/pdf; name="monthly_statement.pdf"
Content-Disposition: attachment; filename="monthly_statement.pdf"
Content-Transfer-Encoding: base64

{PDF_B64}
--===============BOUNDARY_PDF_01==--
""",
    },
    {
        "filename": "attachment_02_clean_png_receipt.eml",
        "category": "Attachment Forensics",
        "expected": "Low",
        "content": f"""Return-Path: <orders@clean-merchant.com>
Received: from mail.clean-merchant.com (mail.clean-merchant.com [198.51.100.24])
    by target.internal with ESMTPS id 9IiI4040;
    Sat, 19 Sep 2026 11:00:00 +0000
Authentication-Results: mx.target.com; spf=pass; dkim=pass header.d=clean-merchant.com; dmarc=pass;
From: "Store Customer Support" <orders@clean-merchant.com>
To: "Buyer" <buyer@target.com>
Subject: Your Order Confirmation and Image Receipt #88921
Date: Sat, 19 Sep 2026 11:00:00 +0000
Message-ID: <att-02-png@clean-merchant.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="===============BOUNDARY_PNG_02=="

--===============BOUNDARY_PNG_02==
Content-Type: text/plain; charset="utf-8"

Thank you for your purchase.
Your order receipt image is attached. Your shipment is scheduled to depart our fulfillment center tomorrow.

--===============BOUNDARY_PNG_02==
Content-Type: image/png; name="order_receipt.png"
Content-Disposition: attachment; filename="order_receipt.png"
Content-Transfer-Encoding: base64

{PNG_B64}
--===============BOUNDARY_PNG_02==--
""",
    },
    {
        "filename": "attachment_03_eicar_test_virus.eml",
        "category": "Attachment Forensics",
        "expected": "Medium",
        "content": f"""Return-Path: <audit@security-lab.org>
Received: from mail.security-lab.org (mail.security-lab.org [198.51.100.26])
    by target.internal with ESMTPS id 0JjJ5050;
    Sat, 19 Sep 2026 11:15:00 +0000
Authentication-Results: mx.target.com; spf=pass; dkim=pass header.d=security-lab.org; dmarc=pass;
From: "Security Compliance Lab" <audit@security-lab.org>
To: "SOC Testing" <soc@target.com>
Subject: Scheduled Anti-Malware Test: Standard EICAR Validation
Date: Sat, 19 Sep 2026 11:15:00 +0000
Message-ID: <att-03-eicar@security-lab.org>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="===============BOUNDARY_EICAR_03=="

--===============BOUNDARY_EICAR_03==
Content-Type: text/plain; charset="utf-8"

SOC Analysts:
This message contains the standard EICAR anti-malware test signature for endpoint scanner validation.
Static analysis engines should identify this payload as malicious.

--===============BOUNDARY_EICAR_03==
Content-Type: application/octet-stream; name="eicar_standard_test.com"
Content-Disposition: attachment; filename="eicar_standard_test.com"
Content-Transfer-Encoding: base64

{EICAR_B64}
--===============BOUNDARY_EICAR_03==--
""",
    },
    {
        "filename": "attachment_04_disguised_executable_pdf.eml",
        "category": "Attachment Forensics",
        "expected": "Critical",
        "content": f"""Return-Path: <hacker@evil-c2.net>
Received: from mx1.target.com (mx1.target.com [198.51.100.99])
    by mailserver.target.internal with ESMTPS id 1KkK6060;
    Sat, 19 Sep 2026 11:30:00 +0000
Authentication-Results: mx1.target.com; spf=fail; dkim=none; dmarc=fail;
From: "HR Benefits Portal" <alerts@payroll-internal-verify.xyz>
To: "Employee" <victim@target.com>
Subject: URGENT: Salary Review Document - Click Attached PDF Immediately
Date: Sat, 19 Sep 2026 11:30:00 +0000
Message-ID: <att-04-exe@payroll-internal-verify.xyz>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="===============BOUNDARY_EXE_04=="

--===============BOUNDARY_EXE_04==
Content-Type: text/plain; charset="utf-8"

URGENT: Your updated compensation and bonus schedule has been released.
Open the attached PDF invoice and confirm your account information immediately:
Claim your salary bonus refund today.

--===============BOUNDARY_EXE_04==
Content-Type: application/pdf; name="salary_increase_notice.pdf"
Content-Disposition: attachment; filename="salary_increase_notice.pdf"
Content-Transfer-Encoding: base64

{PE_STUB_B64}
--===============BOUNDARY_EXE_04==--
""",
    },
    {
        "filename": "attachment_05_benign_macro_document.eml",
        "category": "Attachment Forensics",
        "expected": "Medium",
        "content": f"""Return-Path: <fp-a@target-corp.com>
Received: from mail.target-corp.com (mail.target-corp.com [198.51.100.28])
    by target.internal with ESMTPS id 2LlL7070;
    Sat, 19 Sep 2026 11:45:00 +0000
Authentication-Results: mx.target.com; spf=pass; dkim=pass header.d=target-corp.com; dmarc=pass;
From: "Financial Planning" <fp-a@target-corp.com>
To: "Budget Directors" <directors@target.com>
Subject: Quarterly Budget Model with Macro Automation - Review Copy
Date: Sat, 19 Sep 2026 11:45:00 +0000
Message-ID: <att-05-macro@target-corp.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="===============BOUNDARY_MACRO_05=="

--===============BOUNDARY_MACRO_05==
Content-Type: text/plain; charset="utf-8"

Team,
Attached is our standard quarterly budget modeling document containing our internal lookup macros.
Please enter your departmental forecasts in tab 2.

--===============BOUNDARY_MACRO_05==
Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document; name="budget_model_v3.docx"
Content-Disposition: attachment; filename="budget_model_v3.docx"
Content-Transfer-Encoding: base64

{MACRO_DOCX_B64}
--===============BOUNDARY_MACRO_05==--
""",
    },

    # -------------------------------------------------------------
    # Category 5: Edge Cases
    # -------------------------------------------------------------
    {
        "filename": "edge_01_missing_headers_no_subject.eml",
        "category": "Edge Cases",
        "expected": "Low",
        "content": """From: colleague@partner.org
To: me@target.com

Can you send me the draft slides when you get a chance?
Thanks!
""",
    },
    {
        "filename": "edge_02_unusual_encoding_iso8859.eml",
        "category": "Edge Cases",
        "expected": "Low",
        "content": """Return-Path: <info@conference-geneve.ch>
Received: from mail.conference-geneve.ch ([198.51.100.32])
    by mx1.target.com with ESMTP id 3MmM8080;
    Sat, 19 Sep 2026 12:00:00 +0000
Authentication-Results: mx1.target.com; spf=pass; dkim=pass header.d=conference-geneve.ch; dmarc=pass;
From: "Conference Secretariat" <info@conference-geneve.ch>
To: "Participant" <attendee@target.com>
Subject: Confirmation de votre inscription au colloque
Date: Sat, 19 Sep 2026 12:00:00 +0000
Message-ID: <edge-02-iso@conference-geneve.ch>
MIME-Version: 1.0
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable

Bonjour,

Veuillez trouver ci-joint les d=E9tails de votre participation au colloque =
international.
L'=E9v=E9nement aura lieu =E0 Gen=E8ve la semaine prochaine.

Meilleures salutations,
Le Comit=E9 d'Organisation
""",
    },
    {
        "filename": "edge_03_deep_nested_multipart.eml",
        "category": "Edge Cases",
        "expected": "Low",
        "content": """Return-Path: <newsletter@corporate-news.com>
Received: from mailer.corporate-news.com ([198.51.100.34])
    by mx1.target.com with ESMTP id 4NnN9090;
    Sat, 19 Sep 2026 12:15:00 +0000
Authentication-Results: mx1.target.com; spf=pass; dkim=pass header.d=corporate-news.com; dmarc=pass;
From: "Corporate News Desk" <newsletter@corporate-news.com>
To: "Reader" <reader@target.com>
Subject: Corporate Quarterly Highlights
Date: Sat, 19 Sep 2026 12:15:00 +0000
Message-ID: <edge-03-nested@corporate-news.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="===============OUTER_BOUNDARY=="

--===============OUTER_BOUNDARY==
Content-Type: multipart/alternative; boundary="===============ALT_BOUNDARY=="

--===============ALT_BOUNDARY==
Content-Type: multipart/related; boundary="===============REL_BOUNDARY=="

--===============REL_BOUNDARY==
Content-Type: text/html; charset="utf-8"

<!DOCTYPE html>
<html>
<body>
  <h2>Corporate Quarterly Highlights</h2>
  <p>Our complete quarterly financial presentation is now accessible on the corporate intranet.</p>
  <p>Thank you for your hard work and continued dedication.</p>
</body>
</html>

--===============REL_BOUNDARY==--
--===============ALT_BOUNDARY==--
--===============OUTER_BOUNDARY==--
""",
    },
]


def create_and_evaluate_corpus():
    results: List[Dict[str, Any]] = []

    print(f"Creating and evaluating {len(EMAILS_DEFINITIONS)} stress test emails...\n")

    for item in EMAILS_DEFINITIONS:
        fname = item["filename"]
        fpath = os.path.join(STRESS_DIR, fname)
        with open(fpath, "w", encoding="utf-8", newline="\n") as f:
            f.write(item["content"])

        with open(fpath, "rb") as f:
            raw_bytes = f.read()

        # Execute full pipeline
        report, pdf_bytes = run_full_pipeline_and_generate_report(raw_bytes)

        risk_score = report.threat_assessment.risk_score
        verdict = report.threat_assessment.verdict
        expected = item["expected"]
        match = (verdict.lower() == expected.lower())

        breakdown = report.evidence_fusion.score_breakdown
        factors = report.evidence_fusion.contributing_factors

        results.append({
            "filename": fname,
            "category": item["category"],
            "expected": expected,
            "actual": verdict,
            "risk_score": risk_score,
            "match": match,
            "breakdown": {
                "ml": breakdown.ml_phishing,
                "auth": breakdown.authentication,
                "att": breakdown.attachments,
                "ioc": breakdown.ioc_geo,
            },
            "factors": factors,
            "threat_count": report.threat_assessment.threat_indicators_count,
            "pdf_sha256": report.pdf_sha256,
        })

    return results


if __name__ == "__main__":
    import json
    eval_results = create_and_evaluate_corpus()
    with open("scratch/stress_test_results.json", "w", encoding="utf-8") as out_f:
        json.dump(eval_results, out_f, indent=2)
    print("Stress test completed! Output saved to scratch/stress_test_results.json")
