import React, { useState, useRef, useEffect } from 'react';
import TextareaAutosize from 'react-textarea-autosize';
import styles from './EditView.module.css';

interface EditViewProps {
    initialText: string;
    onFinish: (finalText: string) => void;
}

export default function EditView({ initialText, onFinish, highlightedWords = [] }: EditViewProps & { highlightedWords?: string[] }) {
    const editorRef = useRef<HTMLDivElement>(null);

    // We only use this to track the plain text content for submission
    const [text, setText] = useState(initialText);

    // Generate initial HTML with highlights
    // We only do this ONCE to avoid cursor jumping issues with re-renders
    const [initialHtml] = useState(() => {
        if (!highlightedWords.length) return initialText;

        const escapedWords = highlightedWords
            .filter(w => w.trim().length > 0)
            .map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

        if (escapedWords.length === 0) return initialText;

        // Simply replace all occurrences
        // Note: This is simple replacement. Be careful with HTML injection if text isn't trusted.
        // Assuming initialText is plain text from our own translation step.
        if (escapedWords.length === 0) return initialText;

        // Use word boundaries for exact matching, case insensitive
        // Note: korean might not respond well to \b in all cases, but for mixed text it helps.
        // For Korean, \b matches transitions between word char and non-word char.
        // However, standard regex \b often fails for non-ASCII. 
        // Let's use a simpler approach or a dedicated tokenizer if this were production.
        // For this MVP, we will try to match whitespace boundaries or start/end of string.
        // Pattern: (^|\s)(word)($|\s) - capture groups to preserve whitespace

        // Actually, for simplicity and robustness with Korean, let's stick to simple replacement but try to be careful.
        // Or better: use a function that splits by whitespace and checks exact match.
        // But we want to preserve whitespace usage.

        const pattern = new RegExp(`(${escapedWords.join('|')})`, 'gi');

        return initialText.split(pattern).map(part => {
            // Check if the part roughly matches one of the words (trim check)
            if (highlightedWords.some(w => w.toLowerCase() === part.toLowerCase())) {
                return `<span class="${styles.highlight}">${part}</span>`;
            }
            return part;
        }).join('');
    });

    // Initialize content imperatively to avoid React managing it on subsequent renders
    useEffect(() => {
        if (editorRef.current) {
            editorRef.current.innerHTML = initialHtml;
        }
    }, [initialHtml]);

    const handleInput = (e: React.FormEvent<HTMLDivElement>) => {
        if (e.currentTarget) {
            setText(e.currentTarget.innerText);
        }
    };

    return (
        <div className={styles.container}>
            <h2 className={styles.title}>Finalize Translation</h2>
            <p className={styles.description}>
                Refine the translation below. The box will expand as you type.
            </p>
            <div className={styles.editorWrapper}>
                <div
                    ref={editorRef}
                    className={styles.contentEditable}
                    contentEditable
                    suppressContentEditableWarning
                    onInput={handleInput}
                    spellCheck={false}
                />
            </div>
            <div className={styles.actions}>
                <button className={styles.finishButton} onClick={() => onFinish(text)}>
                    Complete Editing
                </button>
            </div>
        </div>
    );
}
