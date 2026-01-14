import { NextResponse } from 'next/server';
import OpenAI from 'openai';

export async function POST(request: Request) {
    const openai = new OpenAI({
        apiKey: process.env.OPENAI_API_KEY,
    });
    try {
        const { english, korean, selectedWords } = await request.json();

        if (!english || !korean || !selectedWords || !Array.isArray(selectedWords) || selectedWords.length === 0) {
            return NextResponse.json({ error: 'Missing required fields or invalid selectedWords' }, { status: 400 });
        }

        const completion = await openai.chat.completions.create({
            model: 'gpt-4o',
            messages: [
                {
                    role: 'system',
                    content: `You are a helpful Korean language tutor.
          The user is an L2 Korean learner who selected specific words/phrases from a translation to understand them better.
          
          Context:
          English: "${english}"
          Korean Translation: "${korean}"
          
          Selected Words: ${JSON.stringify(selectedWords)}
          
          For EACH selected word, provide an explanation object. Return a JSON object with a single key "explanations" which is an array of objects.
          
          Each object must contain:
          1. "word": The exact Korean word from the list.
          2. "basic": A single string short explanation of meaning.
          3. "extended": A detailed explanation including usage context.
          4. "backTranslation": An object with "original" (the specific English word/phrase from the source text that this maps to) and "back" (the literal English translation of the Korean word/phrase; use a single word or short phrase to allow for nuance comparison, NOT a full sentence).
          5. "alternatives": An array of strings containing 2-3 alternative Korean words/phrases that could be used in this context.
          6. "nativeUsageExamples": A string or array of strings giving 1-2 examples of how/when a native speaker would use this word naturally in this specific context (or similar contexts).
          
          Write the explanation primarily in English.`,
                },
            ],
            response_format: { type: 'json_object' },
        });

        const content = completion.choices[0].message.content;
        if (!content) {
            throw new Error('No content received from OpenAI');
        }

        const result = JSON.parse(content);
        return NextResponse.json(result.explanations);
    } catch (error) {
        console.error('Explanation error:', error);
        return NextResponse.json({ error: 'Explanation failed' }, { status: 500 });
    }
}
