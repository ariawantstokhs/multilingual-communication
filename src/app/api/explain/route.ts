import { NextResponse } from 'next/server';
import OpenAI from 'openai';

export async function POST(request: Request) {
    const openai = new OpenAI({
        apiKey: process.env.OPENAI_API_KEY,
    });
    try {
        const { english, korean, selectedWord } = await request.json();

        if (!english || !korean || !selectedWord) {
            return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
        }

        const completion = await openai.chat.completions.create({
            model: 'gpt-4o',
            messages: [
                {
                    role: 'system',
                    content: `You are a helpful Korean language tutor.
          The user is an L2 Korean learner who selected a specific word/phrase from a translation to understand it better.
          
          Context:
          English: "${english}"
          Korean Translation: "${korean}"
          Selected Word/Phrase: "${selectedWord}"
          
          Provide an explanation in JSON format with two fields:
          1. "basic": A short explanation of the meaning and which part of the English text it corresponds to.
          2. "extended": A detailed explanation including usage context (formal/informal), similar expressions, and why this word was chosen.
          
          Write the explanation primarily in English to help L2 Korean learners understand. You may quote Korean words, but the explanation text itself must be in English.`,
                },
            ],
            response_format: { type: 'json_object' },
        });

        const content = completion.choices[0].message.content;
        if (!content) {
            throw new Error('No content received from OpenAI');
        }

        const result = JSON.parse(content);
        return NextResponse.json(result);
    } catch (error) {
        console.error('Explanation error:', error);
        return NextResponse.json({ error: 'Explanation failed' }, { status: 500 });
    }
}
