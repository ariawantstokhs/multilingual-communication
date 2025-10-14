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

def translate_with_profile(text: str, source_lang: str, sample_texts: list[str], target_language: str) -> Dict[str, str]:
    """
    Translate message using personalized style from sample texts.
    Uses few-shot prompting to apply user's writing style to the target language.
    """
    client = _get_client()

    # Build few-shot examples from sample texts
    sample_examples = "\n".join([f"- {sample}" for sample in sample_texts[:5]])  # Limit to 5 samples

    personalized_prompt = f"""You translate short chat messages.
Return ONLY JSON with keys: text_en, text_ko, text_es, text_ur.

IMPORTANT: For the '{target_language}' translation, use the writing style shown in these examples:
{sample_examples}

Match the tone, vocabulary, sentence structure, and expressions from the examples above when translating to {target_language}.
For other languages, use formal tone. Keep meaning intact. Never add comments."""

    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": personalized_prompt},
                {"role": "user", "content": f"Source language: {source_lang}\nText: {text}"},
            ],
            response_format={"type": "json_object"},
            temperature=0.3,  # Slightly higher for more stylistic variation
        )
        raw = completion.choices[0].message.content
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        # Fallback to standard translation if personalized fails
        return translate_message(text, source_lang)

    return {
        "text_en": data.get("text_en", text),
        "text_ko": data.get("text_ko", text),
        "text_es": data.get("text_es", text),
        "text_ur": data.get("text_ur", text),
    }
