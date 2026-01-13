'use client';

import React, { useState, useEffect } from 'react';
import TranslationView, { TranslatedSentence } from '@/components/TranslationView';
import ExplanationView from '@/components/ExplanationView';
import EditView from '@/components/EditView';
import { ExplanationData } from '@/components/ExplanationCard';
import { demoText } from '@/lib/demoData';
import styles from './page.module.css';

type Step = 'input' | 'translation' | 'explanation' | 'edit';

export default function Home() {
  const [step, setStep] = useState<Step>('input');
  const [inputText, setInputText] = useState(demoText);
  const [sentences, setSentences] = useState<TranslatedSentence[]>([]);
  const [selectedIndices, setSelectedIndices] = useState<Set<string>>(new Set());
  const [explanations, setExplanations] = useState<ExplanationData[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [finalText, setFinalText] = useState('');

  const handleStartTranslation = async () => {
    setStep('translation');
    setIsLoading(true);
    try {
      const response = await fetch('/api/translate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: inputText }),
      });

      console.log('Response Status:', response.status);
      const text = await response.text();
      console.log('Response Body:', text);

      if (!response.ok) {
        throw new Error(`Server error: ${response.status} ${text}`);
      }

      if (!text) {
        throw new Error('Empty response from server');
      }

      const data = JSON.parse(text);
      if (data.sentences) {
        setSentences(data.sentences);
      }
    } catch (error) {
      console.error('Failed to fetch translation', error);
      alert('Translation failed. See console for details.');
      setStep('input'); // Go back to input on failure
    } finally {
      setIsLoading(false);
    }
  };

  const handleWordClick = (sentenceIndex: number, wordIndex: number) => {
    const key = `${sentenceIndex}-${wordIndex}`;
    const newSet = new Set(selectedIndices);
    if (newSet.has(key)) {
      newSet.delete(key);
    } else {
      newSet.add(key);
    }
    setSelectedIndices(newSet);
  };

  const handleGetExplanations = async () => {
    setStep('explanation');
    setIsLoading(true);
    const newExplanations: ExplanationData[] = [];

    try {
      // Fetch explanation for each selected word
      // In a real app, we might batch this.
      for (const key of selectedIndices) {
        const [sIdxStr, wIdxStr] = key.split('-');
        const sIdx = parseInt(sIdxStr);
        const wIdx = parseInt(wIdxStr);
        const sentence = sentences[sIdx];
        const word = sentence.korean.split(' ')[wIdx];

        const response = await fetch('/api/explain', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            english: sentence.english,
            korean: sentence.korean,
            selectedWord: word,
          }),
        });
        const data = await response.json();
        newExplanations.push({
          word,
          basic: data.basic,
          extended: data.extended,
        });
      }
      setExplanations(newExplanations);
    } catch (error) {
      console.error('Failed to fetch explanations', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleEditFinish = (text: string) => {
    setFinalText(text);
    alert('Translation finalized! (Check console for output)');
    console.log('Final Text:', text);
  };

  return (
    <main className={styles.main}>
      <h1 className={styles.header}>MT Understanding Tool</h1>

      {step === 'input' && (
        <div className={styles.inputContainer}>
          <h2 className={styles.sourceTitle}>Enter Source Text (English)</h2>
          <textarea
            className={styles.inputArea}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
          />
          <button className={styles.translateButton} onClick={handleStartTranslation}>
            Translate
          </button>
        </div>
      )}

      {step !== 'input' && (
        <div className={styles.sourceContainer}>
          <h2 className={styles.sourceTitle}>Source Text (English)</h2>
          <div className={styles.sourceText}>{inputText}</div>
        </div>
      )}

      {step === 'translation' && (
        <>
          {isLoading ? (
            <div className={styles.loading}>Translating...</div>
          ) : (
            <TranslationView
              sentences={sentences}
              selectedIndices={selectedIndices}
              onWordClick={handleWordClick}
              onNext={handleGetExplanations}
            />
          )}
        </>
      )}

      {step === 'explanation' && (
        <ExplanationView
          explanations={explanations}
          onNext={() => setStep('edit')}
          isLoading={isLoading}
        />
      )}

      {step === 'edit' && (
        <EditView
          initialText={sentences.map(s => s.korean).join(' ')}
          onFinish={handleEditFinish}
        />
      )}
    </main>
  );
}
