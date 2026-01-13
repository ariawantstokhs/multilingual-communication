import React, { useState } from 'react';
import TextareaAutosize from 'react-textarea-autosize';
import styles from './EditView.module.css';

interface EditViewProps {
    initialText: string;
    onFinish: (finalText: string) => void;
}

export default function EditView({ initialText, onFinish }: EditViewProps) {
    const [text, setText] = useState(initialText);

    return (
        <div className={styles.container}>
            <h2 className={styles.title}>Finalize Translation</h2>
            <p className={styles.description}>
                Refine the translation below. The box will expand as you type.
            </p>
            <div className={styles.editorWrapper}>
                <TextareaAutosize
                    className={styles.textarea}
                    value={text}
                    onChange={(e) => setText(e.target.value)}
                    minRows={10}
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
