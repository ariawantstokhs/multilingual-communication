"""
Post-Editing Analysis Module

Exploratory analysis of user post-editing behavior in machine translation.
Based on: Green, S., Heer, J., & Manning, C. D. (2013). The efficacy of human post-editing for language translation. CHI '13.
"""

import json
import os
from openai import OpenAI


def analyze_post_edits(mt_version: str, edited_version: str) -> dict:
    """
    Exploratory analysis of user post-editing behavior.

    Following Green et al. (2013) who demonstrated that post-editing
    patterns reveal user priorities, we conduct open-ended analysis
    to identify what types of changes users make and why.

    This formative analysis aims to discover patterns rather than
    impose predetermined categories.

    Args:
        mt_version: The machine translation output
        edited_version: The user's edited version

    Returns:
        dict: Open-ended analysis of observed changes and emerging patterns
    """
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    prompt = f"""Analyze what changed between MT output and user's edited version.

MT Output: {mt_version}
User's Version: {edited_version}

For each change you identify:
1. What specifically changed (quote the text)
2. Describe the nature of the change
3. What this might reveal about user's needs/preferences

Don't force changes into predetermined categories - just describe what you observe.

Return JSON:
{{
    "observed_changes": [
        {{
            "mt_text": "original text from MT",
            "user_text": "user's edited version",
            "change_description": "open description of what changed and how",
            "possible_motivation": "why user might have made this change"
        }}
    ],
    "emerging_patterns": "What patterns do you notice across all changes?",
    "user_priorities": "What seems to matter most to this user based on their edits?",
    "implications": "What does this suggest for MT personalization?"
}}

Focus on meaningful changes. Describe observations openly without forcing categorization."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are analyzing post-editing patterns to understand user behavior. Describe what you observe without imposing predetermined categories. Focus on discovering patterns."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Analysis error: {e}")
        return {"error": str(e)}
