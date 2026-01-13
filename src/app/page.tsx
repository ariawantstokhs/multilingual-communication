'use client';

import React, { useState, useEffect } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import TranslationView, { TranslatedSentence } from '@/components/TranslationView';

import EditView from '@/components/EditView';
import ExplanationCard, { ExplanationData } from '@/components/ExplanationCard';
import { demoText } from '@/lib/demoData';
import styles from './page.module.css';

type Step = 'input' | 'translation' | 'edit';

export default function Home() {
  const [step, setStep] = useState<Step>('input');
  const [inputText, setInputText] = useState(demoText);
  const [sentences, setSentences] = useState<TranslatedSentence[]>([]);
  const [selectedIndices, setSelectedIndices] = useState<Set<string>>(new Set());
  const [explanations, setExplanations] = useState<ExplanationData[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [finalText, setFinalText] = useState('');
  const [isSourceVisible, setIsSourceVisible] = useState(false);

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
    setStep('edit'); // Skip standalone explanation view, go straight to edit with sidebar
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

        // Defensive coding: Ensure basic and extended are strings
        // The API might return an object sometimes (e.g. { explanation: "...", part_of_speech: "..." })
        const basicText = typeof data.basic === 'object' && data.basic !== null
          ? (data.basic.explanation || JSON.stringify(data.basic))
          : String(data.basic || '');

        const extendedText = typeof data.extended === 'object' && data.extended !== null
          ? (data.extended.explanation || JSON.stringify(data.extended))
          : String(data.extended || '');

        newExplanations.push({
          word,
          basic: basicText,
          extended: extendedText,
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
      <div className={styles.container}>
        <header className={styles.header}>
          <h1 className={styles.title}>MT Understanding Tool</h1>
          <p className={styles.subtitle}>Translate, Understand, Refine.</p>
        </header>

        {step === 'input' && (
          <div className={styles.card}>
            <div className={styles.cardHeader}>
              <h2 className={styles.cardTitle}>Enter Source Text</h2>
              <span className={styles.badge}>English</span>
            </div>
            <textarea
              className={styles.inputArea}
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Type or paste English text here..."
            />
            <div className={styles.cardFooter}>
              <button
                className={styles.primaryButton}
                onClick={handleStartTranslation}
                disabled={!inputText.trim() || isLoading}
              >
                {isLoading ? 'Translating...' : 'Start Translation'}
              </button>
            </div>
          </div>
        )}

        {step !== 'input' && (
          <div className={styles.collapsibleSource}>
            <button
              className={styles.collapseToggle}
              onClick={() => setIsSourceVisible(!isSourceVisible)}
            >
              <div className={styles.toggleLabel}>
                <span className={styles.badge}>Source Text</span>
                <span className={styles.sourcePreview}>
                  {isSourceVisible ? '' : inputText.slice(0, 50) + (inputText.length > 50 ? '...' : '')}
                </span>
              </div>
              {isSourceVisible ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
            </button>

            {isSourceVisible && (
              <div className={styles.sourceContent}>
                {inputText}
              </div>
            )}
          </div>
        )}

        {step === 'translation' && (
          <div className={styles.translationContainer}>
            {isLoading ? (
              <div className={styles.loadingState}>
                <div className={styles.spinner} />
                <p>Analyzing text and generating translations...</p>
              </div>
            ) : (
              <TranslationView
                sentences={sentences}
                selectedIndices={selectedIndices}
                onWordClick={handleWordClick}
                onNext={handleGetExplanations}
              />
            )}
          </div>
        )}

        {step === 'edit' && (
          <div className={styles.editLayout}>
            <div className={styles.editMain}>
              <EditView
                initialText={sentences.map(s => s.korean).join(' ')}
                onFinish={handleEditFinish}
              />
            </div>
            <aside className={styles.editSidebar}>
              <div className={styles.sidebarHeader}>
                <h3 className={styles.sidebarTitle}>Word Explanations</h3>
                <span className={styles.explanationCount}>{explanations.length} selected</span>
              </div>

              {isLoading ? (
                <div className={styles.loadingState}>
                  <div className={styles.spinner} />
                  <p>Fetching explanations...</p>
                </div>
              ) : (
                <div className={styles.sidebarContent}>
                  {explanations.length === 0 ? (
                    <div className={styles.emptyState}>
                      <p>No words selected for explanation.</p>
                      <p className={styles.emptyHint}>Go back to select words if you need help.</p>
                    </div>
                  ) : (
                    explanations.map((data, idx) => (
                      <ExplanationCard key={idx} data={data} />
                    ))
                  )}
                </div>
              )}
            </aside>
          </div>
        )}
      </div>
    </main>
  );
}
