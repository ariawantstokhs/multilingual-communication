# translation.py
import os, json
from typing import Dict
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())
from openai import OpenAI

SYSTEM_PROMPT = """You translate short chat messages.
Return ONLY JSON with keys: text_en, text_ko, text_es, text_ur.
Keep meaning and tone. If a translation is identical to the source, repeat it verbatim.
Never add comments. Use formal tone in every language.
"""

def _get_client() -> OpenAI:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set (check backend/.env)")
    return OpenAI(api_key=api_key)

def translate_message(text: str, source_lang: str = "en") -> Dict[str, str]:
    client = _get_client()  # create the client when called, not at import
    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Source language: {source_lang}\nText: {text}"},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )
        raw = completion.choices[0].message.content
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        data = {}
    return {
        "text_en": data.get("text_en", text),
        "text_ko": data.get("text_ko", text),
        "text_es": data.get("text_es", text),
        "text_ur": data.get("text_ur", text),
    }


def translate_with_profile(
    text: str, source_lang: str, profile_data: dict, target_language: str = "en"
) -> str:
    """
    Translate text while applying observed user patterns from post-editing analysis.

    Args:
        text: Text to translate
        source_lang: Source language code (e.g., 'ko')
        profile_data: User profile with observed patterns and priorities
        target_language: Target language for translation (default: 'en')

    Returns:
        str: Translated text that matches user's observed patterns
    """
    client = _get_client()

    # Extract observed patterns from profile
    observed_patterns = profile_data.get("observed_patterns", [])
    user_priorities = profile_data.get("user_priorities", [])
    change_motivations = profile_data.get("change_motivations", [])
    summary = profile_data.get("profile_summary", "")

    # Build personalization context from exploratory analysis
    profile_context = f"""
User's Observed Communication Patterns:

Emerging Patterns:
{chr(10).join(['- ' + pattern for pattern in observed_patterns[:5]]) if observed_patterns else '- No patterns observed yet'}

User Priorities:
{chr(10).join(['- ' + priority for priority in user_priorities[:5]]) if user_priorities else '- No specific priorities identified'}

Common Motivations for Changes:
{chr(10).join(['- ' + motivation for motivation in change_motivations[:5]]) if change_motivations else '- No motivations identified yet'}

Profile Summary: {summary}
"""

    personalized_prompt = f"""You translate messages while considering the user's observed editing patterns.

{profile_context}

TRANSLATION INSTRUCTIONS:
1. Consider the patterns that emerged from user's past edits
2. Prioritize what matters most to this user
3. Apply insights from their common motivations for changes
4. Make the translation align with their observed preferences

Return ONLY the translated text in {target_language}. No JSON, no explanation, just the translation."""

    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": personalized_prompt},
                {
                    "role": "user",
                    "content": f"Translate this from {source_lang} to {target_language}:\n{text}",
                },
            ],
            temperature=0.3,
        )
        result = completion.choices[0].message.content
        return result.strip() if result else text
    except Exception as e:
        print(f"Error in personalized translation: {e}")
        # Fallback to original text if translation fails
        return text
