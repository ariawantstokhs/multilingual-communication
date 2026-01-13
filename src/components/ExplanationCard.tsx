import React, { useState } from 'react';
import styles from './ExplanationCard.module.css';

export interface ExplanationData {
    word: string;
    basic: string;
    extended: string;
}

interface ExplanationCardProps {
    data: ExplanationData;
}

export default function ExplanationCard({ data }: ExplanationCardProps) {
    const [expanded, setExpanded] = useState(false);

    return (
        <div className={styles.card}>
            <div className={styles.header}>
                <h3 className={styles.word}>{data.word}</h3>
            </div>
            <div className={styles.basic}>
                <p>{data.basic}</p>
            </div>

            {expanded && (
                <div className={styles.extended}>
                    <div className={styles.divider} />
                    <p className={styles.extendedText}>{data.extended}</p>
                </div>
            )}

            <button
                className={styles.expandButton}
                onClick={() => setExpanded(!expanded)}
            >
                {expanded ? 'Show Less' : 'Show More'}
            </button>
        </div>
    );
}
