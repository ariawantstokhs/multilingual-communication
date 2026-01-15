import React from 'react';
import ExplanationCard, { ExplanationData } from './ExplanationCard';
import styles from './ExplanationView.module.css';

interface ExplanationViewProps {
    explanations: ExplanationData[];
    onNext: () => void;
    isLoading: boolean;
}

export default function ExplanationView({ explanations, onNext, isLoading }: ExplanationViewProps) {
    if (isLoading) {
        return <div className={styles.loading}>Generating explanations...</div>;
    }

    return (
        <div className={styles.container}>
            <h2 className={styles.title}>Step 2: Understand the nuances</h2>
            <div className={styles.grid}>
                {explanations.map((data, idx) => (
                    <ExplanationCard key={idx} data={data} activeTab="explanation" />
                ))}
            </div>
            <button className={styles.nextButton} onClick={onNext}>
                Next: Edit Translation
            </button>
        </div>
    );
}
