"""
CTI-based Identity Gap Analysis

Analyzes Personal-Enacted Identity Gaps between MT and user-edited versions.
"""

import json
import os
from openai import OpenAI


def analyze_identity_gap(mt_version: str, edited_version: str) -> dict:
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    prompt = f"""Analyze the identity gap.

Machine Translation: {mt_version}
User-Edited Version: {edited_version}

The scale has TWO FACTORS based on factor analysis:

FACTOR 1 - INAUTHENTICITY (Items 4,5,6,7,8,9,10):
Where MT causes the user to appear inauthentic. Identify where MT created these issues:
- Item 4: "I express myself in a certain way that is not the real me"
- Item 5: "I do not reveal important aspects of myself"
- Item 6: "I often lose sense of who I am"
- Item 7: "I do not express the real me when different from expectations"
- Item 8: "I sometimes mislead others about who I really am"
- Item 9: "There is a difference between the real me and the impression I give"
- Item 10: "I speak truthfully about myself" (reversed - MT fails this)

FACTOR 2 - AUTHENTICITY (Items 1,2,3,11):
Where user edits restore authentic self-expression. Identify what user restored:
- Item 1: "Others get to know the real me"
- Item 2: "I communicate in a way consistent with who I really am"
- Item 3: "I can be myself when communicating"
- Item 11: "I freely express the real me"

Return JSON:
{{
    "factor1_inauthenticity": [
        {{
            "mt_issue": "The specific MT text that created inauthenticity",
            "user_fix": "How the user corrected it",
            "scale_item": "4, 5, 6, 7, 8, 9, or 10",
            "explanation": "Brief explanation of the identity gap"
        }}
    ],
    "factor2_authenticity": [
        {{
            "mt_failure": "Where MT failed to allow authentic expression",
            "user_restoration": "How the user restored authenticity",
            "scale_item": "1, 2, 3, or 11",
            "explanation": "Brief explanation of what was restored"
        }}
    ],
    "summary": "Overall summary of how user's edits reduce the Personal-Enacted Identity Gap"
}}"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert in Communication Theory of Identity (CTI). Analyze identity gaps using the Personal-Enacted Identity Gap Scale's two-factor structure."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Analysis error: {e}")
        return {"error": str(e)}