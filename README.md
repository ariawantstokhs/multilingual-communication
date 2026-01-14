# MT Understanding Tool

A web application designed to help users translate, understand, and refine English text into Korean using AI-powered machine translation and interactive explanations.

## Overview

The MT Understanding Tool goes beyond simple translation by providing a workflow that helps users understand the *why* behind a translation. It allows users to interact with translated text, get detailed explanations for specific words, and refine the final output with context-awareness.

## Features

The application follows a 3-step workflow:

1.  **Input**: Enter English source text or use the provided demo text.
2.  **Translation**: 
    - Viewing sentence-by-sentence aligned translations.
    - Interactive word selection: Click on Korean words in the translation to mark them for explanation.
3.  **Edit & Understand**:
    - **Word Explanations**: View detailed AI-generated explanations for selected words, including basic meanings and extended context/nuances.
    - **Refinement**: Edit the generated Korean translation to produce a polished final version, utilizing the insights from the explanations.

## Tech Stack

- **Framework**: [Next.js](https://nextjs.org/) (v16) with App Router
- **Language**: [TypeScript](https://www.typescriptlang.org/)
- **UI Library**: [React](https://react.dev/) (v19)
- **Styling**: CSS Modules
- **Icons**: [Lucide React](https://lucide.dev/)
- **AI Integration**: [OpenAI API](https://openai.com/) (GPT models for translation and explanation)

## Getting Started

### Prerequisites

- Node.js (v18 or higher recommended)
- `npm` or `yarn`
- An OpenAI API Key

### Installation

1.  Clone the repository:
    ```bash
    git clone <repository-url>
    cd multilingual-communication
    ```

2.  Install dependencies:
    ```bash
    npm install
    # or
    yarn install
    ```

3.  Environment Setup:
    Create a `.env.local` file in the root directory and add your OpenAI API key:
    ```bash
    OPENAI_API_KEY=your_api_key_here
    ```

### Running the Application

Start the development server:

```bash
npm run dev
# or
yarn dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

## Project Structure

- `src/app`: Next.js App Router pages and API routes (`/api/translate`, `/api/explain`).
- `src/components`: React components for different views (TranslationView, EditView, ExplanationCard, etc.).
- `src/lib`: Utility functions and demo data.
