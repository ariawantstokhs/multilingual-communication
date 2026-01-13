import React from 'react';
import SentencePair from './SentencePair';
import styles from './TranslationView.module.css';

export interface TranslatedSentence {
    english: string;
    korean: string;
}

interface TranslationViewProps {
    sentences: TranslatedSentence[];
    selectedIndices: Set<string>;
    onWordClick: (sentenceIndex: number, wordIndex: number) => void;
    onNext: () => void;
}

export default function TranslationView({
    sentences,
    selectedIndices,
    onWordClick,
    onNext,
}: TranslationViewProps) {
    return (
        <div className={styles.container}>
            <h2 className={styles.title}>Step 1: Select words you don't understand</h2>
            <div className={styles.list}>
                {sentences.map((pair, idx) => (
                    <SentencePair
                        key={idx}
                        english={pair.english}
                        korean={pair.korean}
                        sentenceIndex={idx}
                        selectedIndices={selectedIndices}
                        onWordClick={onWordClick}
                    />
                ))}
            </div>
            <button
                className={styles.nextButton}
                onClick={onNext}
                disabled={selectedIndices.size === 0}
            >
                Next: Get Explanations
            </button>
        </div>
    );
}
