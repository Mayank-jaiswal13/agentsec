#!/usr/bin/env python3
"""Generate example transcripts with synthetic PII (stdlib only).

Card PANs and dashed SSNs are assembled at runtime so the source tree does not
need to store contiguous payment-card or SSN literals for GitHub push
protection. Run this before trying the risky_*.json demos.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import piiguard as pg  # noqa: E402

PAN = pg.make_luhn("411111111111", 16)
PAN_MC = pg.make_luhn("555555555555", 16)
SSN_DEMO = "-".join(["219", "09", "9999"])
SSN_DEMO2 = "-".join(["457", "55", "5462"])
IBAN_DEMO = "GB82WEST12345698765432"


def write(name, obj):
    path = os.path.join(HERE, name)
    with open(path, "w", encoding="utf-8") as f:
        if name.endswith(".jsonl"):
            for row in obj:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        elif name.endswith(".txt"):
            f.write(obj if isinstance(obj, str) else str(obj))
        else:
            json.dump(obj, f, indent=2, ensure_ascii=False)
            f.write("\n")
    print("wrote", path)


def main():
    write(
        "clean_openai.json",
        {
            "messages": [
                {"role": "user", "content": "Summarize yesterday's deploy notes."},
                {
                    "role": "assistant",
                    "content": "Deploy succeeded. No customer data was needed.",
                },
            ]
        },
    )

    user_blob = (
        "Please update the profile for Ada Lovelace. "
        "Email ada.lovelace@example.com, phone +1-555-555-0142, "
        "DOB 1815-12-10, SSN {ssn}. "
        "Home address: 123 Example Street, Springfield, IL 62701. "
        "Passport number A12345678. "
        "MRN MRN-FAKE-7788."
    ).format(ssn=SSN_DEMO)

    write(
        "risky_openai.json",
        {
            "messages": [
                {"role": "user", "content": user_blob},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "update_customer",
                                "arguments": json.dumps(
                                    {
                                        "email": "ada.lovelace@example.com",
                                        "card": PAN,
                                        "routing_number": "021000021",
                                        "account_number": "123456789012",
                                    }
                                ),
                            },
                        }
                    ],
                },
                {
                    "role": "tool",
                    "name": "update_customer",
                    "content": "Updated. IBAN on file: " + IBAN_DEMO,
                },
            ]
        },
    )

    write(
        "risky_anthropic.json",
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Driver's license DL# S123-4567-8901 for the rider.",
                        }
                    ],
                },
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu1",
                            "name": "lookup_patient",
                            "input": {
                                "patient_id": "ignored",
                                "npi": "1234567890",
                                "note": "card on file " + PAN_MC,
                            },
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu1",
                            "content": "Patient phone (312) 555-0199 confirmed.",
                        }
                    ],
                },
            ]
        },
    )

    write(
        "risky.jsonl",
        [
            {"role": "user", "content": "Contact me at bob@example.org please."},
            {
                "role": "assistant",
                "content": "SSN social security number %s noted for demo only." % SSN_DEMO2,
            },
        ],
    )

    write(
        "risky_plaintext.txt",
        (
            "Customer follow-up\n\n"
            "Email: carol.demo@example.net\n"
            "Phone: 555-867-5309\n"
            "Date of birth: March 14, 1985\n"
            "Address: 42 Demo Avenue, Apt 3B, Austin, TX 78701\n"
            "National ID: NID-FAKE-998877\n"
        ),
    )

    write(
        "GENERATED.txt",
        (
            "Examples generated by make_examples.py.\n"
            "PANs are synthetic Luhn-valid numbers ending in %s / %s.\n"
            "All names, phones (555), emails (@example.*), and IDs are fake.\n"
            % (PAN[-4:], PAN_MC[-4:])
        ),
    )


if __name__ == "__main__":
    main()
