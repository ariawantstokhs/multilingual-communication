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
