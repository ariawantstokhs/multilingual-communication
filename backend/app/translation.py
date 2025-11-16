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


def translate_with_gap_analysis(
    text: str, source_lang: str, gap_analysis: dict, target_language: str = "en"
) -> str:
    """
    Translate text while preserving identity markers identified from CTI gap analysis.
    Uses the two-factor structure from Jung & Hecht (2004).

    Args:
        text: Text to translate
        source_lang: Source language code (e.g., 'ko')
        gap_analysis: Gap analysis result with CTI two-factor patterns
        target_language: Target language for translation (default: 'en')

    Returns:
        str: Translated text that preserves user's identity markers
    """
    client = _get_client()

    # Extract identity patterns from CTI two-factor analysis
    inauthenticity_fixes = gap_analysis.get("common_inauthenticity_fixes", [])
    authenticity_patterns = gap_analysis.get("common_authenticity_patterns", [])
    summary = gap_analysis.get("identity_summary", "")

    # Build identity preservation prompt based on CTI factors
    identity_context = f"""
User's Communication Identity Profile (based on CTI Personal-Enacted Identity Gap Scale):

FACTOR 1 - What the user fixes to avoid inauthenticity:
{chr(10).join(['- ' + fix for fix in inauthenticity_fixes[:5]]) if inauthenticity_fixes else '- No patterns identified yet'}

FACTOR 2 - How the user restores authentic self-expression:
{chr(10).join(['- ' + pattern for pattern in authenticity_patterns[:5]]) if authenticity_patterns else '- No patterns identified yet'}

Identity Summary: {summary}
"""

    personalized_prompt = f"""You translate messages while preserving the user's authentic communication identity.

{identity_context}

CRITICAL INSTRUCTIONS based on CTI Personal-Enacted Identity Gap:
1. Avoid the inauthenticity patterns - don't make the same mistakes MT typically makes
2. Apply the user's authentic expression patterns to make the translation sound like them
3. Ensure the translation allows the "real me" to come through (Factor 2, item 1)
4. Make sure the translation is consistent with who the user really is (Factor 2, item 2)
5. Let the user "be themselves" through the translation (Factor 2, item 3)
6. Allow free expression of the real self (Factor 2, item 11)

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
        print(f"Error in identity-preserving translation: {e}")
        # Fallback to original text if translation fails
        return text
