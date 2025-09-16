export interface User {
  username: string;
  preferred_language: 'en' | 'ko' | 'es' | 'ur';
}

export interface Message {
  _id?: string;
  sender: string;
  timestamp: string;
  original_text: string;
  original_language: string;
  text_en: string;
  text_ko: string;
  text_es: string;
  text_ur: string;
}

export interface TranslatedMessage {
  [key: string]: string;
  text_en: string;
  text_ko: string;
  text_es: string;
  text_ur: string;
}