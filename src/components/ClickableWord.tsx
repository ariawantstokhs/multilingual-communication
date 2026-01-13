import React from 'react';
import styles from './ClickableWord.module.css';

interface ClickableWordProps {
    word: string;
    index: number;
    isSelected: boolean;
    onClick: (index: number) => void;
}

export default function ClickableWord({ word, index, isSelected, onClick }: ClickableWordProps) {
    return (
        <span
            className={`${styles.word} ${isSelected ? styles.selected : ''}`}
            onClick={() => onClick(index)}
        >
            {word}
        </span>
    );
}
