import React from 'react';
import ClickableWord from './ClickableWord';
import styles from './SentencePair.module.css';

interface SentencePairProps {
    english: string;
    korean: string;
    sentenceIndex: number;
    selectedIndices: Set<string>; // Format: "sentenceIndex-wordIndex"
    onWordClick: (sentenceIndex: number, wordIndex: number) => void;
}

export default function SentencePair({
    english,
    korean,
    sentenceIndex,
    selectedIndices,
    onWordClick,
}: SentencePairProps) {
    const koreanWords = korean.split(' ');

    return (
        <div className={styles.container}>
            <div className={styles.english}>{english}</div>
            <div className={styles.korean}>
                {koreanWords.map((word, idx) => (
                    <ClickableWord
                        key={idx}
                        word={word}
                        index={idx}
                        isSelected={selectedIndices.has(`${sentenceIndex}-${idx}`)}
                        onClick={(wordIndex) => onWordClick(sentenceIndex, wordIndex)}
                    />
                ))}
            </div>
        </div>
    );
}
