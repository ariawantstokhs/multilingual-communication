import React, { useState } from 'react';
import styles from './ExplanationCard.module.css';

export interface ExplanationData {
    word: string;
    basic: string;
    extended: string;
    backTranslation: {
        original: string;
        back: string;
    };
    alternatives?: string[];
    nativeUsageExamples: string | string[];
}

export type TabType = 'explanation' | 'comparison' | 'examples';

interface ExplanationCardProps {
    data: ExplanationData;
    activeTab: TabType;
}

export default function ExplanationCard({ data, activeTab }: ExplanationCardProps) {
    const examples = Array.isArray(data.nativeUsageExamples)
        ? data.nativeUsageExamples
        : [data.nativeUsageExamples];

    return (
        <div className={styles.card}>
            <div className={styles.header}>
                <h3 className={styles.word}>{data.word}</h3>
            </div>

            <div className={styles.tabContent}>
                {activeTab === 'explanation' && (
                    <>
                        <div className={styles.section}>
                            <p className={styles.basicText}>{data.basic}</p>
                        </div>
                        {data.extended && (
                            <div className={styles.section}>
                                <h4 className={styles.sectionTitle}>More Detail</h4>
                                <p className={styles.extendedText}>{data.extended}</p>
                            </div>
                        )}
                        {data.alternatives && data.alternatives.length > 0 && (
                            <div className={styles.alternativesBox}>
                                <span className={styles.altLabel}>Alternatives:</span>
                                {data.alternatives.map((alt, i) => (
                                    <span key={i} className={styles.altTag}>{alt}</span>
                                ))}
                            </div>
                        )}
                    </>
                )}

                {activeTab === 'comparison' && (
                    <div className={styles.comparisonContainer}>
                        <div className={styles.comparisonRow}>
                            <span className={styles.comparisonLabel}>Original English</span>
                            <span className={styles.comparisonText}>{data.backTranslation.original}</span>
                        </div>
                        <div className={styles.comparisonRow}>
                            <span className={styles.comparisonLabel}>Back-Translation</span>
                            <span className={styles.comparisonText}>{data.backTranslation.back}</span>
                        </div>
                    </div>
                )}

                {activeTab === 'examples' && (
                    <div className={styles.usageList}>
                        {examples.map((ex, idx) => (
                            <div key={idx} className={styles.usageItem}>
                                {ex}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
