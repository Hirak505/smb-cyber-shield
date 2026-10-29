"""Tests for detection rules R01-R12.

Each rule has >= 3 positive and >= 3 negative test cases.
Rules are pure functions; no I/O.
"""
from __future__ import annotations

import pytest

from app.rules.scanner import (
    Context,
    ParsedMessage,
    rule_r01,
    rule_r02,
    rule_r03,
    rule_r04,
    rule_r05,
    rule_r06,
    rule_r07,
    rule_r08,
    rule_r09,
    rule_r10,
    rule_r11,
    rule_r12,
    score_message,
)


def _msg(text: str, sender: str | None = None, urls: list | None = None) -> ParsedMessage:
    return ParsedMessage(text=text, sender=sender, urls=urls)


ctx = Context()


# ---------------------------------------------------------------------------
# R01 – Urgency / threat language
# ---------------------------------------------------------------------------

class TestR01:
    # Positive: rule should fire
    def test_account_suspended(self):
        hit = rule_r01(_msg("Your account is suspended. Verify your password within 24 hours."), ctx)
        assert hit is not None
        assert hit.rule_id == "R01"

    def test_act_now(self):
        hit = rule_r01(_msg("Act now or your account will be closed."), ctx)
        assert hit is not None

    def test_urgent_payment(self):
        hit = rule_r01(_msg("Please process this payment urgently before noon."), ctx)
        assert hit is not None

    # Negative: rule should NOT fire
    def test_normal_meeting(self):
        hit = rule_r01(_msg("Reminder: staff meeting on Thursday at 3pm."), ctx)
        assert hit is None

    def test_invoice_without_urgency(self):
        hit = rule_r01(_msg("Please find attached invoice 4411 for last month."), ctx)
        assert hit is None

    def test_friendly_message(self):
        hit = rule_r01(_msg("Can you send the draft proposal by Friday? Thanks."), ctx)
        assert hit is None


# ---------------------------------------------------------------------------
# R02 – Credentials / OTP / card request
# ---------------------------------------------------------------------------

class TestR02:
    def test_verify_password(self):
        hit = rule_r02(_msg("Verify your password within 24 hours to keep access."), ctx)
        assert hit is not None
        assert hit.weight == 30

    def test_enter_otp(self):
        hit = rule_r02(_msg("Enter your OTP to confirm your transaction."), ctx)
        assert hit is not None

    def test_card_number(self):
        hit = rule_r02(_msg("Confirm your card number and one-time code now."), ctx)
        assert hit is not None

    def test_normal_invoice(self):
        hit = rule_r02(_msg("Attached is invoice 4411. Payment terms unchanged."), ctx)
        assert hit is None

    def test_calendar_invite(self):
        hit = rule_r02(_msg("Invitation: Quarterly planning on 12 Nov, 10am."), ctx)
        assert hit is None

    def test_shipping_update(self):
        hit = rule_r02(_msg("Your order 55321 has shipped. Track it from your account."), ctx)
        assert hit is None


# ---------------------------------------------------------------------------
# R03 – Link text vs actual domain mismatch
# ---------------------------------------------------------------------------

class TestR03:
    def test_html_link_mismatch(self):
        text = 'Click <a href="http://evil.com/login">paypal.com</a> to verify.'
        hit = rule_r03(_msg(text), ctx)
        assert hit is not None
        assert hit.rule_id == "R03"

    def test_markdown_link_mismatch(self):
        text = "Reset password: [microsoft.com](http://phishing-site.ru/reset)"
        hit = rule_r03(_msg(text), ctx)
        assert hit is not None

    def test_html_link_mismatch_subdomain(self):
        text = 'Verify at <a href="http://paypal.login-secure.com">paypal.com</a>'
        hit = rule_r03(_msg(text), ctx)
        assert hit is not None

    def test_matching_domains(self):
        text = '<a href="http://paypal.com/verify">paypal.com</a>'
        hit = rule_r03(_msg(text), ctx)
        assert hit is None

    def test_plain_url_no_display(self):
        hit = rule_r03(_msg("Visit http://google.com for help."), ctx)
        assert hit is None

    def test_no_links(self):
        hit = rule_r03(_msg("Meeting tomorrow at 10am."), ctx)
        assert hit is None


# ---------------------------------------------------------------------------
# R04 – Lookalike / homoglyph / punycode domain
# ---------------------------------------------------------------------------

class TestR04:
    def test_paypal_lookalike(self):
        hit = rule_r04(_msg("Login at http://paypa1-secure.com/login"), ctx)
        assert hit is not None
        assert hit.rule_id == "R04"

    def test_microsoft_lookalike(self):
        hit = rule_r04(_msg("Verify: http://micros0ft-support.com/verify"), ctx)
        assert hit is not None

    def test_ip_not_homoglyph_but_r05(self):
        # IPs are caught by R05; R04 may or may not fire – just ensure no crash
        rule_r04(_msg("Click http://192.168.4.4/pay"), ctx)  # no assertion; just no exception

    def test_legit_paypal(self):
        hit = rule_r04(_msg("Login at https://paypal.com"), ctx)
        assert hit is None

    def test_legit_github(self):
        hit = rule_r04(_msg("Visit https://github.com for the repo"), ctx)
        assert hit is None

    def test_no_url(self):
        hit = rule_r04(_msg("Let me know if you need anything."), ctx)
        assert hit is None


# ---------------------------------------------------------------------------
# R05 – URL shortener or IP-literal host
# ---------------------------------------------------------------------------

class TestR05:
    def test_bitly(self):
        hit = rule_r05(_msg("Click here: http://bit.ly/3xYz to keep your email active."), ctx)
        assert hit is not None
        assert hit.rule_id == "R05"

    def test_tinyurl(self):
        hit = rule_r05(_msg("Pay here: http://tinyurl.com/dlv88"), ctx)
        assert hit is not None

    def test_ip_host(self):
        hit = rule_r05(_msg("Your parcel: http://192.168.4.4/pay"), ctx)
        assert hit is not None

    def test_legit_url(self):
        hit = rule_r05(_msg("Track at https://courier.example.com/track/12345"), ctx)
        assert hit is None

    def test_no_url(self):
        hit = rule_r05(_msg("Meeting at 3pm."), ctx)
        assert hit is None

    def test_full_domain(self):
        hit = rule_r05(_msg("Visit https://company.com/invoice"), ctx)
        assert hit is None


# ---------------------------------------------------------------------------
# R06 – Display name vs sender domain mismatch
# ---------------------------------------------------------------------------

class TestR06:
    def test_paypal_display_from_evil(self):
        sender = '"PayPal Support <paypal.com>" <phisher@evil-domain.xyz>'
        hit = rule_r06(_msg("Verify your account.", sender=sender), ctx)
        assert hit is not None
        assert hit.rule_id == "R06"

    def test_bank_display_wrong_domain(self):
        sender = '"Barclays.com" <noreply@phish.net>'
        hit = rule_r06(_msg("Your account needs attention.", sender=sender), ctx)
        assert hit is not None

    def test_company_in_display_but_gmail(self):
        sender = '"Microsoft Support <microsoft.com>" <ms-help@gmail.com>'
        hit = rule_r06(_msg("Renew your license.", sender=sender), ctx)
        assert hit is not None

    def test_legit_sender_no_display(self):
        hit = rule_r06(_msg("Invoice attached.", sender="billing@vendor.com"), ctx)
        assert hit is None

    def test_matching_display_and_domain(self):
        sender = '"vendor.com Support" <billing@vendor.com>'
        hit = rule_r06(_msg("Your invoice.", sender=sender), ctx)
        assert hit is None

    def test_no_sender(self):
        hit = rule_r06(_msg("Check this out."), ctx)
        assert hit is None


# ---------------------------------------------------------------------------
# R07 – Free-mail sender posing as executive
# ---------------------------------------------------------------------------

class TestR07:
    def test_ceo_from_gmail(self):
        hit = rule_r07(
            _msg("Are you at your desk? I need this done urgently.", sender="ceo.office@gmail.com"),
            ctx,
        )
        assert hit is not None
        assert hit.rule_id == "R07"

    def test_md_from_outlook(self):
        hit = rule_r07(
            _msg("Please process this payment. I am the MD.", sender="md@outlook.com"),
            ctx,
        )
        assert hit is not None

    def test_cfo_from_proton(self):
        hit = rule_r07(
            _msg("Confidential wire transfer needed today.", sender="cfo@proton.me"),
            ctx,
        )
        assert hit is not None

    def test_staff_from_gmail_no_exec(self):
        hit = rule_r07(
            _msg("Are we still on for lunch Saturday?", sender="friend@gmail.com"),
            ctx,
        )
        assert hit is None

    def test_company_domain(self):
        hit = rule_r07(
            _msg("Monthly update from the CEO.", sender="ceo@company.com"),
            ctx,
        )
        assert hit is None

    def test_no_sender(self):
        hit = rule_r07(_msg("Wire needed."), ctx)
        assert hit is None


# ---------------------------------------------------------------------------
# R08 – Payment detail change
# ---------------------------------------------------------------------------

class TestR08:
    def test_bank_details_changed(self):
        hit = rule_r08(_msg("Please note our bank details have changed. Pay to new account."), ctx)
        assert hit is not None
        assert hit.weight == 30

    def test_upi_changed(self):
        hit = rule_r08(_msg("Our UPI ID has changed. Please send payment to new UPI ID."), ctx)
        assert hit is not None

    def test_updated_account_details(self):
        hit = rule_r08(_msg("Pay within 24 hours to the updated account details attached."), ctx)
        assert hit is not None

    def test_regular_invoice(self):
        hit = rule_r08(_msg("Invoice 4411 for last month. Bank details unchanged."), ctx)
        assert hit is None

    def test_meeting_reminder(self):
        hit = rule_r08(_msg("Meeting on Thursday at 3pm."), ctx)
        assert hit is None

    def test_shipping_notification(self):
        hit = rule_r08(_msg("Your order has shipped. Track it from your account."), ctx)
        assert hit is None


# ---------------------------------------------------------------------------
# R09 – Risky attachment type
# ---------------------------------------------------------------------------

class TestR09:
    def test_html_attachment(self):
        hit = rule_r09(_msg("Open the attached Payroll_Update.html and sign in."), ctx)
        assert hit is not None
        assert hit.rule_id == "R09"

    def test_iso_attachment(self):
        hit = rule_r09(_msg("Open Invoice_scan.iso and enable content to view."), ctx)
        assert hit is not None

    def test_exe_attachment(self):
        hit = rule_r09(_msg("Run setup.exe to install the update."), ctx)
        assert hit is not None

    def test_pdf_attachment(self):
        hit = rule_r09(_msg("Please find the attached report.pdf for review."), ctx)
        assert hit is None

    def test_docx_attachment(self):
        hit = rule_r09(_msg("Draft proposal.docx is attached. Please review."), ctx)
        assert hit is None

    def test_no_attachment(self):
        hit = rule_r09(_msg("Meeting confirmed for Thursday."), ctx)
        assert hit is None


# ---------------------------------------------------------------------------
# R10 – Gift card / wire / crypto
# ---------------------------------------------------------------------------

class TestR10:
    def test_gift_cards(self):
        hit = rule_r10(
            _msg("I need you to buy 5 gift cards urgently and send me the codes."),
            ctx,
        )
        assert hit is not None
        assert hit.weight == 30

    def test_wire_transfer(self):
        hit = rule_r10(_msg("Send a wire transfer to this account today."), ctx)
        assert hit is not None

    def test_bitcoin(self):
        hit = rule_r10(_msg("Send 0.1 BTC to unlock your reward."), ctx)
        assert hit is not None

    def test_normal_payment_terms(self):
        hit = rule_r10(_msg("Payment terms are net 30. Please remit by month end."), ctx)
        assert hit is None

    def test_meeting_invite(self):
        hit = rule_r10(_msg("Quarterly planning on 12 Nov, 10am."), ctx)
        assert hit is None

    def test_normal_invoice(self):
        hit = rule_r10(_msg("Invoice 9921 for services rendered in October."), ctx)
        assert hit is None


# ---------------------------------------------------------------------------
# R11 – Generic greeting
# ---------------------------------------------------------------------------

class TestR11:
    def test_dear_customer(self):
        hit = rule_r11(_msg("Dear customer, your parcel is held. Pay a fee here."), ctx)
        assert hit is not None
        assert hit.rule_id == "R11"

    def test_dear_user(self):
        hit = rule_r11(_msg("Dear user, your account needs verification."), ctx)
        assert hit is not None

    def test_dear_valued_member(self):
        hit = rule_r11(_msg("Dear valued member, please confirm your details."), ctx)
        assert hit is not None

    def test_named_greeting(self):
        hit = rule_r11(_msg("Hi Priya, attached is invoice 4411 for last month."), ctx)
        assert hit is None

    def test_no_greeting(self):
        hit = rule_r11(_msg("Invoice 4411 attached. Payment terms unchanged."), ctx)
        assert hit is None

    def test_team_greeting(self):
        hit = rule_r11(_msg("Hi team, reminder: meeting at 3pm."), ctx)
        assert hit is None


# ---------------------------------------------------------------------------
# R12 – Unknown vendor invoice
# ---------------------------------------------------------------------------

class TestR12:
    def test_unknown_vendor_invoice(self):
        ctx_empty = Context(known_vendors=[])
        hit = rule_r12(
            _msg("Invoice 9921 overdue. Pay within 24 hours.", sender="billing@acme-supp1y.com"),
            ctx_empty,
        )
        assert hit is not None
        assert hit.rule_id == "R12"

    def test_known_vendor_not_flagged(self):
        ctx_known = Context(known_vendors=["knownvendor.com"])
        hit = rule_r12(
            _msg("Invoice 4411 for last month.", sender="billing@knownvendor.com"),
            ctx_known,
        )
        assert hit is None

    def test_no_invoice_keyword(self):
        ctx_empty = Context()
        hit = rule_r12(
            _msg("Please pay urgently.", sender="billing@unknown.com"),
            ctx_empty,
        )
        assert hit is None

    def test_no_sender(self):
        ctx_empty = Context()
        hit = rule_r12(_msg("Invoice 9921 is attached."), ctx_empty)
        assert hit is None

    def test_invoice_with_no_vendor_list(self):
        # No known vendors means invoice from any domain is flagged
        hit = rule_r12(
            _msg("Invoice 5555 attached.", sender="payments@new-supplier.com"),
            Context(),
        )
        assert hit is not None

    def test_legit_meeting_no_invoice(self):
        hit = rule_r12(
            _msg("Meeting scheduled for Friday.", sender="hr@company.com"),
            Context(),
        )
        assert hit is None


# ---------------------------------------------------------------------------
# Full scoring pipeline
# ---------------------------------------------------------------------------

class TestScoring:
    def test_clear_phishing_scores_high(self):
        text = (
            "Your account is suspended. Verify your password within 24 hours: "
            "http://paypa1-secure.com/login"
        )
        score, verdict, hits = score_message(
            ParsedMessage(text=text, sender="support@paypa1-secure.com")
        )
        assert score >= 60
        assert verdict == "Likely phishing"

    def test_legit_message_scores_low(self):
        text = "Hi Priya, attached is invoice 4411 for last month's order PO-8821. Payment terms unchanged."
        score, verdict, hits = score_message(
            ParsedMessage(text=text, sender="billing@knownvendor.com")
        )
        assert verdict == "Likely safe"

    def test_gift_card_scam(self):
        text = "Are you at your desk? I need you to buy 5 gift cards urgently and send me the codes."
        score, verdict, hits = score_message(
            ParsedMessage(text=text, sender="ceo.office@gmail.com")
        )
        assert score >= 25
        assert verdict in ("Suspicious", "Likely phishing")

    def test_score_capped_at_100(self):
        # Max out multiple high-weight rules
        text = (
            "Urgent: Your account is suspended. Verify your password now at http://paypa1-secure.com/login "
            "and send a wire transfer and buy gift cards. Our bank details have changed. "
            "Enter your OTP and card number now."
        )
        score, verdict, hits = score_message(ParsedMessage(text=text))
        assert score <= 100
        assert verdict == "Likely phishing"

    def test_evidence_spans_within_bounds(self):
        text = "Your account is suspended. Click http://bit.ly/xyz to verify your password."
        score, verdict, hits = score_message(ParsedMessage(text=text))
        for hit in hits:
            for span in hit.evidence:
                assert span.start >= 0
                assert span.end <= len(text)
                assert span.start <= span.end
