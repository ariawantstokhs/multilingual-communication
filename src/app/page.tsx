'use client';

import React, { useState, useEffect } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import TranslationView, { TranslatedSentence } from '@/components/TranslationView';

import EditView from '@/components/EditView';
import ExplanationCard, { ExplanationData } from '@/components/ExplanationCard';
import { demoText } from '@/lib/demoData';
import styles from './page.module.css';

type Step = 'input' | 'translation' | 'edit';
type TabType = 'explanation' | 'comparison' | 'examples';

export default function Home() {
  const [step, setStep] = useState<Step>('input');
  const [inputText, setInputText] = useState(demoText);
  const [sentences, setSentences] = useState<TranslatedSentence[]>([]);
  const [selectedIndices, setSelectedIndices] = useState<Set<string>>(new Set());
  const [explanations, setExplanations] = useState<ExplanationData[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [finalText, setFinalText] = useState('');
  const [isSourceVisible, setIsSourceVisible] = useState(false);
  const [activeTab, setActiveTab] = useState<TabType>('explanation');

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
    setStep('edit');
    setIsLoading(true);

    try {
      const selectedWordsList: string[] = [];

      // 1. Convert Set to array of objects { sIdx, wIdx }
      const sortedSelections = Array.from(selectedIndices).map(key => {
        const [sIdxStr, wIdxStr] = key.split('-');
        return { sIdx: parseInt(sIdxStr), wIdx: parseInt(wIdxStr) };
      });

      // 2. Sort by sentence index, then word index
      sortedSelections.sort((a, b) => {
        if (a.sIdx !== b.sIdx) return a.sIdx - b.sIdx;
        return a.wIdx - b.wIdx;
      });

      // 3. Group consecutive words
      let currentPhrase: string[] = [];
      let lastSIdx = -1;
      let lastWIdx = -1;

      for (const { sIdx, wIdx } of sortedSelections) {
        if (sentences[sIdx]) {
          const words = sentences[sIdx].korean.split(' ');
          const word = words[wIdx];

          if (word) {
            // Check if this word is consecutive to the last one
            const isConsecutive = (sIdx === lastSIdx) && (wIdx === lastWIdx + 1);

            if (isConsecutive) {
              currentPhrase.push(word);
            } else {
              // Not consecutive: push previous phrase if exists, start new one
              if (currentPhrase.length > 0) {
                selectedWordsList.push(currentPhrase.join(' '));
              }
              currentPhrase = [word];
            }

            lastSIdx = sIdx;
            lastWIdx = wIdx;
          }
        }
      }

      // Push the final phrase if any
      if (currentPhrase.length > 0) {
        selectedWordsList.push(currentPhrase.join(' '));
      }

      if (selectedWordsList.length === 0) {
        setIsLoading(false);
        return;
      }

      const fullEnglish = sentences.map(s => s.english).join(' ');
      const fullKorean = sentences.map(s => s.korean).join(' ');

      const response = await fetch('/api/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          english: fullEnglish,
          korean: fullKorean,
          selectedWords: selectedWordsList,
        }),
      });

      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }

      const data = await response.json();
      // Expecting data to be an array of ExplanationData
      setExplanations(data);

    } catch (error) {
      console.error('Failed to fetch explanations', error);
      alert('Failed to get explanations. Please try again.');
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
                highlightedWords={explanations.map(e => e.word)}
              />
            </div>
            <aside className={styles.editSidebar}>
              <div className={styles.sidebarHeader}>
                <div className={styles.headerTop}>
                  <h3 className={styles.sidebarTitle}>Word Explanations</h3>
                  <span className={styles.explanationCount}>{explanations.length} selected</span>
                </div>
                <div className={styles.tabBar}>
                  <button
                    className={`${styles.tabButton} ${activeTab === 'explanation' ? styles.activeTab : ''}`}
                    onClick={() => setActiveTab('explanation')}
                  >
                    설명 (Explain)
                  </button>
                  <button
                    className={`${styles.tabButton} ${activeTab === 'comparison' ? styles.activeTab : ''}`}
                    onClick={() => setActiveTab('comparison')}
                  >
                    비교 (Diff)
                  </button>
                  <button
                    className={`${styles.tabButton} ${activeTab === 'examples' ? styles.activeTab : ''}`}
                    onClick={() => setActiveTab('examples')}
                  >
                    예시 (Ex.)
                  </button>
                </div>
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
                      <ExplanationCard
                        key={idx}
                        data={data}
                        activeTab={activeTab}
                      />
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
