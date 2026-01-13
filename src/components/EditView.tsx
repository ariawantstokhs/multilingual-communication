import React, { useState } from 'react';
import styles from './EditView.module.css';

interface EditViewProps {
    initialText: string;
    onFinish: (finalText: string) => void;
}

export default function EditView({ initialText, onFinish }: EditViewProps) {
    const [text, setText] = useState(initialText);

    return (
        <div className={styles.container}>
            <h2 className={styles.title}>Step 3: Finalize your translation</h2>
            <p className={styles.description}>
                Based on the explanations, refine the translation to sound more natural or accurate.
            </p>
            <textarea
                className={styles.textarea}
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={10}
            />
            <button className={styles.finishButton} onClick={() => onFinish(text)}>
                Finish
            </button>
        </div>
    );
}
