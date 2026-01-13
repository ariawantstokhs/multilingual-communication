import { NextResponse } from 'next/server';
import OpenAI from 'openai';

export async function POST(request: Request) {
    const openai = new OpenAI({
        apiKey: process.env.OPENAI_API_KEY,
    });
    try {
        console.log('API Key present:', !!process.env.OPENAI_API_KEY);
        const body = await request.json();
        const { text } = body;
        console.log('Received text length:', text?.length);

        if (!text) {
            return NextResponse.json({ error: 'Text is required' }, { status: 400 });
        }

        console.log('Calling OpenAI...');
        const completion = await openai.chat.completions.create({
            model: 'gpt-4o',
            messages: [
                {
                    role: 'system',
                    content: `You are a professional translator. Translate the following English text to a formal, high-register business Korean (incorporating advanced vocabulary/grammar suitable for L2 learners to study).
          Return the result as a JSON object with a "sentences" array, where each object has "english" and "korean" fields.
          Ensure the translation is natural but maintains sentence-level correspondence.`,
                },
                {
                    role: 'user',
                    content: text,
                },
            ],
            response_format: { type: 'json_object' },
        });

        const content = completion.choices[0].message.content;
        console.log('OpenAI response content length:', content?.length);

        if (!content) {
            throw new Error('No content received from OpenAI');
        }

        const result = JSON.parse(content);
        return NextResponse.json(result);
    } catch (error: any) {
        console.error('Translation error:', error);
        const errorMessage = error?.message || 'Unknown error';
        return NextResponse.json({ error: 'Translation failed', details: errorMessage }, { status: 500 });
    }
}
