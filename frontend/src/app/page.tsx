'use client';
import { useState, useEffect } from 'react';

// Types for CTI Gap Analysis (Based on Personal-Enacted Identity Gap Scale - Jung & Hecht 2004)
interface Factor1Inauthenticity {
  mt_issue: string;
  user_fix: string;
  scale_item: string;
  explanation: string;
}

interface Factor2Authenticity {
  mt_failure: string;
  user_restoration: string;
  scale_item: string;
  explanation: string;
}

interface GapAnalysisResult {
  factor1_inauthenticity: Factor1Inauthenticity[];
  factor2_authenticity: Factor2Authenticity[];
  summary: string;
}

interface PersonalProfile {
  common_inauthenticity_fixes: string[];
  inauthenticity_scale_items: Record<string, number>;
  common_authenticity_patterns: string[];
  authenticity_scale_items: Record<string, number>;
  identity_summary: string;
  analysis_count: number;
  last_updated?: string;
  is_active: boolean;
}

interface StoredAnalysis {
  id: string;
  mt_version: string;
  edited_version: string;
  analysis_result: GapAnalysisResult;
  created_at: string;
}

const LANGUAGES = {
  en: 'English',
  ko: '한국어',
  es: 'Español',
  ur: 'اردو'
} as const;

// Hardcoded API URL for localhost testing
const API_URL = 'http://localhost:8000';

// Gap Analysis Modal Component (Reused from original)
function GapAnalysisModal({
  onClose,
  onAnalysisComplete,
  initialMtText = '',
  initialEditedText = ''
}: {
  onClose: () => void;
  onAnalysisComplete: (result: GapAnalysisResult) => void;
  initialMtText?: string;
  initialEditedText?: string;
}) {
  const [mtVersion, setMtVersion] = useState(initialMtText);
  const [editedVersion, setEditedVersion] = useState(initialEditedText);
  const [analysisResult, setAnalysisResult] = useState<GapAnalysisResult | null>(null);
  const [history, setHistory] = useState<StoredAnalysis[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState<'analyze' | 'history'>('analyze');

  useEffect(() => {
    if (activeTab === 'history') {
      loadHistory();
    }
  }, [activeTab]);

  const loadHistory = () => {
    const stored = localStorage.getItem('gap_analysis_history');
    if (stored) {
      try {
        setHistory(JSON.parse(stored));
      } catch {
        setHistory([]);
      }
    }
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mtVersion.trim() || !editedVersion.trim()) {
      setError('Please fill in all fields');
      return;
    }

    setIsAnalyzing(true);
    setError('');
    setAnalysisResult(null);

    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mt_version: mtVersion.trim(),
          edited_version: editedVersion.trim()
        })
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Analysis failed');
      }

      const result = await response.json();
      setAnalysisResult(result);

      // Save to localStorage history
      const newAnalysis: StoredAnalysis = {
        id: Date.now().toString(),
        mt_version: mtVersion.trim(),
        edited_version: editedVersion.trim(),
        analysis_result: result,
        created_at: new Date().toISOString()
      };

      const existingHistory = localStorage.getItem('gap_analysis_history');
      const historyArray: StoredAnalysis[] = existingHistory ? JSON.parse(existingHistory) : [];
      historyArray.unshift(newAnalysis);
      // Keep only last 50 analyses
      const trimmedHistory = historyArray.slice(0, 50);
      localStorage.setItem('gap_analysis_history', JSON.stringify(trimmedHistory));

      onAnalysisComplete(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const renderAnalysisResult = (result: GapAnalysisResult) => (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-purple-50 to-indigo-50 p-4 rounded-lg border border-purple-200">
        <h4 className="font-semibold text-purple-900 mb-2">Identity Gap Summary</h4>
        <p className="text-purple-800">{result.summary}</p>
      </div>

      {result.factor1_inauthenticity.length > 0 && (
        <div className="bg-red-50 p-4 rounded-lg border border-red-200">
          <h4 className="font-semibold text-red-900 mb-3">Factor 1: Inauthenticity Corrections</h4>
          <p className="text-xs text-red-700 mb-3">Where MT caused you to appear inauthentic (Scale items 4,5,6,7,8,9,10)</p>
          <div className="space-y-3">
            {result.factor1_inauthenticity.map((issue, i) => (
              <div key={i} className="bg-white p-3 rounded border border-red-100">
                <div className="flex justify-between items-start mb-2">
                  <span className="text-xs bg-red-100 text-red-700 px-2 py-1 rounded font-medium">
                    Scale Item {issue.scale_item}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 mb-2">
                  <div>
                    <p className="text-xs font-medium text-red-600">MT Issue:</p>
                    <p className="text-sm text-gray-700 line-through">{issue.mt_issue}</p>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-green-600">Your Fix:</p>
                    <p className="text-sm text-gray-900 font-medium">{issue.user_fix}</p>
                  </div>
                </div>
                <p className="text-xs text-red-700 italic">{issue.explanation}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {result.factor2_authenticity.length > 0 && (
        <div className="bg-green-50 p-4 rounded-lg border border-green-200">
          <h4 className="font-semibold text-green-900 mb-3">Factor 2: Authenticity Restorations</h4>
          <p className="text-xs text-green-700 mb-3">How you restored authentic self-expression (Scale items 1,2,3,11)</p>
          <div className="space-y-3">
            {result.factor2_authenticity.map((restoration, i) => (
              <div key={i} className="bg-white p-3 rounded border border-green-100">
                <div className="flex justify-between items-start mb-2">
                  <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded font-medium">
                    Scale Item {restoration.scale_item}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 mb-2">
                  <div>
                    <p className="text-xs font-medium text-red-600">MT Failure:</p>
                    <p className="text-sm text-gray-700">{restoration.mt_failure}</p>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-green-600">Your Restoration:</p>
                    <p className="text-sm text-gray-900 font-medium">{restoration.user_restoration}</p>
                  </div>
                </div>
                <p className="text-xs text-green-700 italic">{restoration.explanation}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-2xl p-6 max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-gray-900">CTI Identity Gap Analysis</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
          </button>
        </div>

        <div className="flex space-x-4 mb-6 border-b">
          <button
            onClick={() => setActiveTab('analyze')}
            className={`pb-2 px-4 font-medium ${activeTab === 'analyze' ? 'border-b-2 border-purple-500 text-purple-600' : 'text-gray-500 hover:text-gray-700'}`}
          >
            Analyze New
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`pb-2 px-4 font-medium ${activeTab === 'history' ? 'border-b-2 border-purple-500 text-purple-600' : 'text-gray-500 hover:text-gray-700'}`}
          >
            History ({history.length})
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
            {error}
          </div>
        )}

        {activeTab === 'analyze' ? (
          <div>
            {!analysisResult ? (
              <form onSubmit={handleAnalyze} className="space-y-4">
                <div className="bg-purple-50 p-4 rounded-lg mb-4">
                  <p className="text-sm text-purple-800">
                    <strong>How it works:</strong> Enter the machine translation and your edited version.
                    We'll analyze what identity markers you restored to understand your authentic communication style.
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Machine Translation Result
                  </label>
                  <textarea
                    value={mtVersion}
                    onChange={(e) => setMtVersion(e.target.value)}
                    placeholder="Paste the machine translation here..."
                    className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 text-gray-700"
                    rows={4}
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Your Edited Version (How you would actually say it)
                  </label>
                  <textarea
                    value={editedVersion}
                    onChange={(e) => setEditedVersion(e.target.value)}
                    placeholder="Edit the translation to match your authentic voice..."
                    className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 text-gray-700"
                    rows={4}
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={isAnalyzing}
                  className="w-full bg-gradient-to-r from-purple-500 to-indigo-600 text-white font-semibold py-3 px-4 rounded-lg hover:from-purple-600 hover:to-indigo-700 disabled:opacity-50"
                >
                  {isAnalyzing ? (
                    <span className="flex items-center justify-center">
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                      Analyzing Identity Gaps...
                    </span>
                  ) : (
                    'Analyze My Communication Identity'
                  )}
                </button>
              </form>
            ) : (
              <div>
                <button
                  onClick={() => {
                    setAnalysisResult(null);
                    setMtVersion('');
                    setEditedVersion('');
                  }}
                  className="mb-4 text-purple-600 hover:text-purple-700 font-medium"
                >
                  ← Analyze Another
                </button>
                {renderAnalysisResult(analysisResult)}
              </div>
            )}
          </div>
        ) : (
          <div>
            {history.length === 0 ? (
              <p className="text-center text-gray-500 py-8">No analysis history yet. Start by analyzing your first translation!</p>
            ) : (
              <div className="space-y-6">
                {history.map((item) => (
                  <div key={item.id} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex justify-between items-start mb-3">
                      <div className="text-xs text-gray-500">
                        {new Date(item.created_at).toLocaleDateString()} at {new Date(item.created_at).toLocaleTimeString()}
                      </div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4 text-sm">
                      <div className="bg-gray-50 p-2 rounded">
                        <p className="font-medium text-gray-600 mb-1">MT Version:</p>
                        <p className="text-gray-800">{item.mt_version}</p>
                      </div>
                      <div className="bg-gray-50 p-2 rounded">
                        <p className="font-medium text-gray-600 mb-1">Your Edit:</p>
                        <p className="text-gray-800">{item.edited_version}</p>
                      </div>
                    </div>
                    <details className="group">
                      <summary className="cursor-pointer text-purple-600 hover:text-purple-700 font-medium text-sm">
                        View Analysis Results
                      </summary>
                      <div className="mt-3">
                        {renderAnalysisResult(item.analysis_result)}
                      </div>
                    </details>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// Profile Modal Component
function ProfileModal({ profile, onClose, onRebuild }: {
  profile: PersonalProfile | null;
  onClose: () => void;
  onRebuild: () => void;
}) {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-2xl p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-gray-900">Your Identity Profile</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
          </button>
        </div>

        {profile && profile.analysis_count > 0 ? (
          <div className="space-y-6">
            <div className="bg-gradient-to-r from-purple-50 to-indigo-50 p-4 rounded-lg border border-purple-200">
              <h4 className="font-semibold text-purple-900 mb-2">Identity Summary</h4>
              <p className="text-purple-800">{profile.identity_summary}</p>
            </div>

            {profile.common_inauthenticity_fixes.length > 0 && (
              <div className="bg-red-50 p-4 rounded-lg border border-red-200">
                <h4 className="font-semibold text-red-900 mb-3">Common Inauthenticity Fixes</h4>
                <div className="flex flex-wrap gap-2">
                  {profile.common_inauthenticity_fixes.map((fix, i) => (
                    <span key={i} className="bg-white text-red-700 px-3 py-1 rounded-full text-sm border border-red-200">
                      {fix}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {profile.common_authenticity_patterns.length > 0 && (
              <div className="bg-green-50 p-4 rounded-lg border border-green-200">
                <h4 className="font-semibold text-green-900 mb-3">Common Authenticity Patterns</h4>
                <div className="flex flex-wrap gap-2">
                  {profile.common_authenticity_patterns.map((pattern, i) => (
                    <span key={i} className="bg-white text-green-700 px-3 py-1 rounded-full text-sm border border-green-200">
                      {pattern}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="text-sm text-gray-600">
              Built from {profile.analysis_count} {profile.analysis_count === 1 ? 'analysis' : 'analyses'}
              {profile.last_updated && (
                <span> • Last updated: {new Date(profile.last_updated).toLocaleDateString()}</span>
              )}
            </div>

            <button
              onClick={onRebuild}
              className="w-full bg-purple-500 text-white py-2 px-4 rounded-lg hover:bg-purple-600"
            >
              Rebuild Profile from History
            </button>
          </div>
        ) : (
          <div className="text-center py-8">
            <p className="text-gray-600 mb-4">No profile built yet. Analyze some translations first!</p>
            <button
              onClick={onRebuild}
              className="bg-purple-500 text-white py-2 px-6 rounded-lg hover:bg-purple-600"
            >
              Build Profile from History
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// Main Translation Interface
function TranslationInterface() {
  const [sourceText, setSourceText] = useState('');
  const [translatedText, setTranslatedText] = useState('');
  const [sourceLang, setSourceLang] = useState<keyof typeof LANGUAGES>('en');
  const [targetLang, setTargetLang] = useState<keyof typeof LANGUAGES>('ko');
  const [isTranslating, setIsTranslating] = useState(false);
  const [useProfile, setUseProfile] = useState(false);
  const [personalProfile, setPersonalProfile] = useState<PersonalProfile | null>(null);
  const [showGapAnalysisModal, setShowGapAnalysisModal] = useState(false);
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [error, setError] = useState('');

  // Load profile from localStorage on mount
  useEffect(() => {
    const stored = localStorage.getItem('personal_profile');
    if (stored) {
      try {
        setPersonalProfile(JSON.parse(stored));
      } catch {
        setPersonalProfile(null);
      }
    }
  }, []);

  const buildProfileFromHistory = () => {
    const historyStr = localStorage.getItem('gap_analysis_history');
    if (!historyStr) {
      alert('No analysis history found. Please analyze some translations first.');
      return;
    }

    const history: StoredAnalysis[] = JSON.parse(historyStr);
    if (history.length === 0) {
      alert('No analysis history found. Please analyze some translations first.');
      return;
    }

    // Aggregate patterns from all analyses
    const allInauthenticityFixes: string[] = [];
    const allAuthenticityPatterns: string[] = [];
    const inauthenticityItemCounts: Record<string, number> = {};
    const authenticityItemCounts: Record<string, number> = {};

    for (const analysis of history) {
      const result = analysis.analysis_result;

      for (const issue of result.factor1_inauthenticity) {
        if (issue.user_fix) {
          allInauthenticityFixes.push(issue.user_fix);
        }
        if (issue.scale_item) {
          inauthenticityItemCounts[issue.scale_item] = (inauthenticityItemCounts[issue.scale_item] || 0) + 1;
        }
      }

      for (const restoration of result.factor2_authenticity) {
        if (restoration.user_restoration) {
          allAuthenticityPatterns.push(restoration.user_restoration);
        }
        if (restoration.scale_item) {
          authenticityItemCounts[restoration.scale_item] = (authenticityItemCounts[restoration.scale_item] || 0) + 1;
        }
      }
    }

    // Get most frequent patterns
    const fixCounts = allInauthenticityFixes.reduce((acc, fix) => {
      acc[fix] = (acc[fix] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    const topFixes = Object.entries(fixCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([fix]) => fix);

    const patternCounts = allAuthenticityPatterns.reduce((acc, pattern) => {
      acc[pattern] = (acc[pattern] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    const topPatterns = Object.entries(patternCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([pattern]) => pattern);

    // Create summary
    let summary = `Based on ${history.length} analyses using CTI Personal-Enacted Identity Gap Scale: `;
    if (Object.keys(inauthenticityItemCounts).length > 0) {
      const mostCommonIssue = Object.entries(inauthenticityItemCounts).sort(([, a], [, b]) => b - a)[0][0];
      summary += `Most common inauthenticity issue is scale item ${mostCommonIssue}. `;
    }
    if (Object.keys(authenticityItemCounts).length > 0) {
      const mostCommonAuth = Object.entries(authenticityItemCounts).sort(([, a], [, b]) => b - a)[0][0];
      summary += `Most common authenticity restoration is scale item ${mostCommonAuth}. `;
    }
    if (topPatterns.length > 0) {
      summary += `User frequently restores: ${topPatterns.slice(0, 3).join(', ')}.`;
    }

    const newProfile: PersonalProfile = {
      common_inauthenticity_fixes: topFixes,
      inauthenticity_scale_items: inauthenticityItemCounts,
      common_authenticity_patterns: topPatterns,
      authenticity_scale_items: authenticityItemCounts,
      identity_summary: summary.trim(),
      analysis_count: history.length,
      last_updated: new Date().toISOString(),
      is_active: true
    };

    setPersonalProfile(newProfile);
    localStorage.setItem('personal_profile', JSON.stringify(newProfile));
    alert('Profile built successfully!');
  };

  const handleTranslate = async () => {
    if (!sourceText.trim()) {
      setError('Please enter text to translate');
      return;
    }

    if (sourceLang === targetLang) {
      setTranslatedText(sourceText);
      return;
    }

    setIsTranslating(true);
    setError('');

    try {
      const response = await fetch(`${API_URL}/translate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: sourceText.trim(),
          source_lang: sourceLang,
          target_lang: targetLang,
          use_profile: useProfile && personalProfile !== null,
          profile_data: useProfile ? personalProfile : null
        })
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Translation failed');
      }

      const result = await response.json();
      setTranslatedText(result.translated_text);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Translation failed');
    } finally {
      setIsTranslating(false);
    }
  };

  const swapLanguages = () => {
    const tempLang = sourceLang;
    setSourceLang(targetLang);
    setTargetLang(tempLang);
    setSourceText(translatedText);
    setTranslatedText(sourceText);
  };

  const handleAnalysisComplete = (result: GapAnalysisResult) => {
    console.log('Analysis complete:', result);
    // Optionally rebuild profile after each analysis
    buildProfileFromHistory();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 via-white to-purple-100">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-purple-100">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <h1 className="text-2xl font-bold text-gray-900">
            Identity-Aware Translator
          </h1>
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setShowProfileModal(true)}
              className="flex items-center space-x-2 bg-purple-100 text-purple-700 px-4 py-2 rounded-lg hover:bg-purple-200 transition-colors"
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <circle cx="12" cy="7" r="4" stroke="currentColor" strokeWidth="2"/>
              </svg>
              <span>Profile</span>
              {personalProfile && (
                <span className="bg-purple-500 text-white text-xs px-2 py-0.5 rounded-full">
                  {personalProfile.analysis_count}
                </span>
              )}
            </button>
            <button
              onClick={() => setShowGapAnalysisModal(true)}
              className="flex items-center space-x-2 bg-gradient-to-r from-purple-500 to-indigo-600 text-white px-4 py-2 rounded-lg hover:from-purple-600 hover:to-indigo-700 transition-colors"
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <span>Gap Analysis</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Translation Area */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {error && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
            {error}
          </div>
        )}

        {/* Language Selection Bar */}
        <div className="bg-white rounded-t-2xl shadow-sm border border-purple-100 p-4">
          <div className="flex items-center justify-center space-x-4">
            <select
              value={sourceLang}
              onChange={(e) => setSourceLang(e.target.value as keyof typeof LANGUAGES)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent text-gray-700"
            >
              {Object.entries(LANGUAGES).map(([code, name]) => (
                <option key={code} value={code}>{name}</option>
              ))}
            </select>

            <button
              onClick={swapLanguages}
              className="p-2 bg-purple-100 rounded-full hover:bg-purple-200 transition-colors"
              title="Swap languages"
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" className="text-purple-600">
                <path d="M7 16l-4-4m0 0l4-4m-4 4h18M17 8l4 4m0 0l-4 4m4-4H3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>

            <select
              value={targetLang}
              onChange={(e) => setTargetLang(e.target.value as keyof typeof LANGUAGES)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent text-gray-700"
            >
              {Object.entries(LANGUAGES).map(([code, name]) => (
                <option key={code} value={code}>{name}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Translation Panels */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-0 bg-white rounded-b-2xl shadow-lg border border-t-0 border-purple-100 overflow-hidden">
          {/* Source Text Panel */}
          <div className="border-r border-purple-100">
            <div className="p-4 border-b border-purple-50 bg-gray-50">
              <span className="text-sm font-medium text-gray-600">Source Text</span>
            </div>
            <textarea
              value={sourceText}
              onChange={(e) => setSourceText(e.target.value)}
              placeholder="Enter text to translate..."
              className="w-full h-64 p-4 resize-none focus:outline-none text-gray-800 placeholder-gray-400"
            />
            <div className="p-4 border-t border-purple-50 flex items-center justify-between">
              <span className="text-xs text-gray-500">{sourceText.length} characters</span>
              <button
                onClick={handleTranslate}
                disabled={isTranslating || !sourceText.trim()}
                className="bg-gradient-to-r from-purple-500 to-indigo-600 text-white px-6 py-2 rounded-lg hover:from-purple-600 hover:to-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium transition-all"
              >
                {isTranslating ? (
                  <span className="flex items-center">
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                    Translating...
                  </span>
                ) : (
                  'Translate'
                )}
              </button>
            </div>
          </div>

          {/* Target Text Panel */}
          <div>
            <div className="p-4 border-b border-purple-50 bg-gray-50 flex items-center justify-between">
              <span className="text-sm font-medium text-gray-600">Translation</span>
              {personalProfile && personalProfile.analysis_count > 0 && (
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useProfile}
                    onChange={(e) => setUseProfile(e.target.checked)}
                    className="w-4 h-4 text-purple-600 rounded focus:ring-purple-500"
                  />
                  <span className="text-xs text-gray-600">Use Identity Profile</span>
                </label>
              )}
            </div>
            <div className="w-full h-64 p-4 bg-white text-gray-800 overflow-y-auto">
              {translatedText || (
                <span className="text-gray-400">Translation will appear here...</span>
              )}
            </div>
            <div className="p-4 border-t border-purple-50 flex items-center justify-between">
              <span className="text-xs text-gray-500">{translatedText.length} characters</span>
              {translatedText && (
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => navigator.clipboard.writeText(translatedText)}
                    className="text-purple-600 hover:text-purple-700 text-sm font-medium"
                    title="Copy to clipboard"
                  >
                    Copy
                  </button>
                  <button
                    onClick={() => {
                      setShowGapAnalysisModal(true);
                    }}
                    className="text-indigo-600 hover:text-indigo-700 text-sm font-medium"
                    title="Analyze this translation"
                  >
                    Analyze
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Profile Status */}
        {personalProfile && personalProfile.analysis_count > 0 && (
          <div className="mt-6 bg-white rounded-xl shadow-sm border border-purple-100 p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className={`w-3 h-3 rounded-full ${useProfile ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                <span className="text-sm text-gray-700">
                  Identity Profile: {useProfile ? 'Active' : 'Inactive'}
                </span>
                <span className="text-xs text-gray-500">
                  ({personalProfile.analysis_count} analyses)
                </span>
              </div>
              <button
                onClick={buildProfileFromHistory}
                className="text-sm text-purple-600 hover:text-purple-700 font-medium"
              >
                Rebuild Profile
              </button>
            </div>
          </div>
        )}
      </main>

      {/* Modals */}
      {showGapAnalysisModal && (
        <GapAnalysisModal
          onClose={() => setShowGapAnalysisModal(false)}
          onAnalysisComplete={handleAnalysisComplete}
          initialMtText={translatedText}
          initialEditedText=""
        />
      )}

      {showProfileModal && (
        <ProfileModal
          profile={personalProfile}
          onClose={() => setShowProfileModal(false)}
          onRebuild={buildProfileFromHistory}
        />
      )}
    </div>
  );
}

// Main App Component
export default function Home() {
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    setIsClient(true);
  }, []);

  if (!isClient) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-100 via-white to-purple-50">
        <div className="text-center">
          <div className="w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  return <TranslationInterface />;
}
