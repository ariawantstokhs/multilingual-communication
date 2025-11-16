"""
CTI-based Identity Gap Analysis

Analyzes Personal-Enacted Identity Gaps between MT and user-edited versions.
"""

import json
import os
from openai import OpenAI


def analyze_identity_gap(mt_version: str, edited_version: str) -> dict:
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    prompt = f"""Analyze the Personal-Enacted Identity Gap between machine translation and user-edited version.

Machine Translation: {mt_version}
User-Edited Version: {edited_version}

Identify specific instances where MT created identity gaps and user edits restored authentic self-expression.

Use these validated criteria (Personal-Enacted Identity Gap Scale) to identify gaps:
- User expresses themselves in ways that are not the real them
- User does not reveal important aspects of themselves
- User loses sense of who they are
- User does not express real self when different from expectations
- User misleads others about who they really are
- There is difference between real self and impression given
- User cannot speak truthfully about themselves
- Others cannot get to know the real user
- User cannot communicate consistently with who they really are
- User cannot be themselves when communicating
- User cannot freely express the real them

For each change, identify how MT violated these criteria and how user edits restored authenticity.

Return JSON:
{{
    "identity_gaps": [
        {{
            "mt_text": "The specific MT text that created the gap",
            "user_edit": "How the user changed it",
            "gap_type": "Brief category (e.g., formality mismatch, tone shift, cultural expression, emotional authenticity)",
            "explanation": "How this change reduces the identity gap and restores authentic expression"
        }}
    ],
    "summary": "Overall summary of how the user's edits reduce the Personal-Enacted Identity Gap"
}}

Focus on meaningful changes that affect how authentically the user can express their identity."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert in Communication Theory of Identity (CTI). Analyze Personal-Enacted Identity Gaps - the discrepancy between who someone is and how they express themselves in communication."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Analysis error: {e}")
        return {"error": str(e)}