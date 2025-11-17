'use client';
import { useState, useEffect } from 'react';

// Types for Exploratory Post-Editing Analysis (Based on Green et al. 2013)
interface ObservedChange {
  mt_text: string;
  user_text: string;
  change_description: string;
  possible_motivation: string;
}

interface PostEditAnalysisResult {
  observed_changes: ObservedChange[];
  emerging_patterns: string;
  user_priorities: string;
  implications: string;
}

interface PersonalProfile {
  observed_patterns: string[];
  user_priorities: string[];
  change_motivations: string[];
  profile_summary: string;
  analysis_count: number;
  last_updated?: string;
  is_active: boolean;
}

interface StoredAnalysis {
  id: string;
  mt_version: string;
  edited_version: string;
  analysis_result: PostEditAnalysisResult;
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

// Quick Stats Component
function AnalysisQuickStats({
  result
}: {
  result: PostEditAnalysisResult;
}) {
  const totalChanges = result.observed_changes.length;

  return (
    <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
      <h4 className="font-semibold text-blue-900 mb-3 flex items-center gap-2">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" className="text-blue-600">
          <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
        Quick Summary
      </h4>
      <div className="text-center mb-4">
        <div className="text-3xl font-bold text-blue-700">{totalChanges}</div>
        <div className="text-sm text-blue-600">Changes Observed</div>
      </div>

      {result.user_priorities && (
        <div className="bg-white rounded p-3 border border-blue-100">
          <p className="text-xs font-medium text-blue-700 mb-1">User Priorities:</p>
          <p className="text-sm text-blue-800">{result.user_priorities}</p>
        </div>
      )}
    </div>
  );
}

// Analysis Modal Component
function AnalysisModal({
  onClose,
  onAnalysisComplete,
  initialMtText = '',
  initialEditedText = ''
}: {
  onClose: () => void;
  onAnalysisComplete: (result: PostEditAnalysisResult) => void;
  initialMtText?: string;
  initialEditedText?: string;
}) {
  const [mtVersion, setMtVersion] = useState(initialMtText);
  const [editedVersion, setEditedVersion] = useState(initialEditedText);
  const [analysisResult, setAnalysisResult] = useState<PostEditAnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState('');

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

      const existingHistory = localStorage.getItem('post_edit_analysis_history');
      const historyArray: StoredAnalysis[] = existingHistory ? JSON.parse(existingHistory) : [];
      historyArray.unshift(newAnalysis);
      // Keep only last 50 analyses
      const trimmedHistory = historyArray.slice(0, 50);
      localStorage.setItem('post_edit_analysis_history', JSON.stringify(trimmedHistory));

      onAnalysisComplete(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const renderAnalysisResult = (result: PostEditAnalysisResult) => (
    <div className="space-y-6">
      {/* Quick Stats */}
      <AnalysisQuickStats result={result} />

      {/* Emerging Patterns */}
      {result.emerging_patterns && (
        <div className="bg-gradient-to-r from-purple-50 to-indigo-50 p-4 rounded-lg border border-purple-200">
          <h4 className="font-semibold text-purple-900 mb-2">Emerging Patterns</h4>
          <p className="text-purple-800 text-sm">{result.emerging_patterns}</p>
        </div>
      )}

      {/* Implications */}
      {result.implications && (
        <div className="bg-indigo-50 p-4 rounded-lg border border-indigo-200">
          <h4 className="font-semibold text-indigo-900 mb-2">Implications for Personalization</h4>
          <p className="text-indigo-800 text-sm">{result.implications}</p>
        </div>
      )}

      {/* Observed Changes */}
      {result.observed_changes.length > 0 && (
        <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
          <h4 className="font-semibold text-gray-900 mb-3">
            Observed Changes ({result.observed_changes.length})
          </h4>
          <div className="space-y-3">
            {result.observed_changes.map((change, i) => (
              <div key={i} className="bg-white p-3 rounded border border-gray-200">
                <div className="flex items-center gap-2 mb-2">
                  <span className="line-through text-red-500 text-sm">{change.mt_text}</span>
                  <span className="text-gray-400">→</span>
                  <span className="font-medium text-green-700 text-sm">{change.user_text}</span>
                </div>
                <p className="text-xs text-gray-600 mb-1">
                  <strong>What changed:</strong> {change.change_description}
                </p>
                <p className="text-xs text-gray-600">
                  <strong>Possible motivation:</strong> {change.possible_motivation}
                </p>
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
          <h2 className="text-2xl font-bold text-gray-900">Translation Analysis</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
            {error}
          </div>
        )}

        <div>
          {!analysisResult ? (
            <form onSubmit={handleAnalyze} className="space-y-4">
              <div className="bg-purple-50 p-4 rounded-lg mb-4">
                <p className="text-sm text-purple-800">
                  <strong>How it works:</strong> Enter the machine translation and your edited version.
                  We&apos;ll explore your editing patterns to discover what matters to you.
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
                  placeholder="Edit the translation to match how you would express it..."
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
                    Analyzing Patterns...
                  </span>
                ) : (
                  'Discover My Patterns'
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
      </div>
    </div>
  );
}

// Profile Modal Component
function ProfileModal({ profile, onClose, onRebuild, onClear }: {
  profile: PersonalProfile | null;
  onClose: () => void;
  onRebuild: () => void;
  onClear: () => void;
}) {
  const [history, setHistory] = useState<StoredAnalysis[]>([]);
  const [activeTooltip, setActiveTooltip] = useState<string | null>(null);
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  // Load history when modal opens
  useEffect(() => {
    const stored = localStorage.getItem('post_edit_analysis_history');
    if (stored) {
      try {
        setHistory(JSON.parse(stored));
      } catch {
        setHistory([]);
      }
    }
  }, []);

  // Render changes for a single analysis
  const renderChanges = (result: PostEditAnalysisResult, historyId: string) => {
    return (
      <div className="space-y-2">
        {result.observed_changes.map((change, i) => {
          const tooltipId = `${historyId}-change-${i}`;
          return (
            <div
              key={i}
              className="relative"
              onMouseEnter={() => setActiveTooltip(tooltipId)}
              onMouseLeave={() => setActiveTooltip(null)}
            >
              <div className="bg-white px-3 py-2 rounded border border-gray-200 text-xs cursor-help hover:bg-gray-50 transition-colors">
                <div className="flex items-center gap-2">
                  <span className="line-through text-red-400">{change.mt_text}</span>
                  <span className="text-gray-400">→</span>
                  <span className="font-medium text-green-700">{change.user_text}</span>
                </div>
              </div>
              {activeTooltip === tooltipId && (
                <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 z-50 pointer-events-none">
                  <div className="bg-gray-900 text-white text-xs rounded py-2 px-3 max-w-sm whitespace-normal">
                    <div className="font-medium mb-1">{change.change_description}</div>
                    <div className="text-gray-300">{change.possible_motivation}</div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  };

  const totalChanges = history.reduce((sum, item) => sum + item.analysis_result.observed_changes.length, 0);

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-2xl p-6 max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto shadow-2xl border border-gray-200" onClick={(e) => e.stopPropagation()}>
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-gray-900">Your Communication Profile</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
          </button>
        </div>

        {/* Summary Section */}
        {profile && profile.analysis_count > 0 && (
          <div className="bg-gradient-to-r from-purple-50 to-indigo-50 p-4 rounded-lg border border-purple-200 mb-6">
            <div className="flex justify-between items-start mb-2">
              <h4 className="font-semibold text-purple-900">Profile Summary</h4>
              <span className="text-xs text-purple-600">
                {history.length} {history.length === 1 ? 'analysis' : 'analyses'} • {totalChanges} total changes
              </span>
            </div>
            <p className="text-purple-800 text-sm mb-3">{profile.profile_summary}</p>

            {/* Profile Details */}
            <div className="space-y-3 text-sm">
              {profile.observed_patterns.length > 0 && (
                <div>
                  <span className="font-medium text-purple-700">Observed Patterns:</span>
                  <ul className="list-disc list-inside mt-1 text-purple-800">
                    {profile.observed_patterns.slice(0, 3).map((pattern, i) => (
                      <li key={i} className="text-xs">{pattern}</li>
                    ))}
                  </ul>
                </div>
              )}
              {profile.user_priorities.length > 0 && (
                <div>
                  <span className="font-medium text-purple-700">User Priorities:</span>
                  <ul className="list-disc list-inside mt-1 text-purple-800">
                    {profile.user_priorities.slice(0, 3).map((priority, i) => (
                      <li key={i} className="text-xs">{priority}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}

        {/* History List */}
        {history.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-gray-600 mb-4">No analyses yet. Start by analyzing your first translation!</p>
          </div>
        ) : (
          <div className="space-y-3">
            {history.map((item) => {
              const changeCount = item.analysis_result.observed_changes.length;
              return (
                <details key={item.id} className="group border border-gray-200 rounded-lg hover:border-purple-200 transition-colors">
                  <summary className="cursor-pointer p-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" className="transform group-open:rotate-90 transition-transform text-purple-600">
                        <path d="M9 18l6-6-6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                      <span className="text-sm font-medium text-gray-700">
                        {changeCount} {changeCount === 1 ? 'change' : 'changes'} observed
                      </span>
                    </div>
                    <span className="text-xs text-gray-500">
                      {new Date(item.created_at).toLocaleDateString()}
                    </span>
                  </summary>
                  <div className="px-4 pb-4 pt-2 border-t border-gray-100">
                    {item.analysis_result.emerging_patterns && (
                      <p className="text-xs text-gray-600 mb-3">
                        <strong>Patterns:</strong> {item.analysis_result.emerging_patterns}
                      </p>
                    )}
                    {renderChanges(item.analysis_result, item.id)}
                  </div>
                </details>
              );
            })}
          </div>
        )}

        {/* Action Buttons */}
        {history.length > 0 && (
          <div className="mt-6 space-y-3">
            <button
              onClick={onRebuild}
              className="w-full bg-purple-500 text-white py-2 px-4 rounded-lg hover:bg-purple-600 text-sm"
            >
              Rebuild Profile
            </button>
            <button
              onClick={() => setShowClearConfirm(true)}
              className="w-full bg-red-50 text-red-600 py-2 px-4 rounded-lg hover:bg-red-100 text-sm border border-red-200"
            >
              Clear Profile & History
            </button>
          </div>
        )}

        {/* Clear Confirmation Dialog */}
        {showClearConfirm && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[60]" onClick={() => setShowClearConfirm(false)}>
            <div className="bg-white rounded-xl p-6 max-w-md w-full mx-4" onClick={(e) => e.stopPropagation()}>
              <h3 className="text-lg font-semibold text-gray-900 mb-3">Clear Profile?</h3>
              <p className="text-sm text-gray-600 mb-4">
                This will permanently delete your profile and all analysis history. Your translations will no longer be personalized.
              </p>
              <div className="flex space-x-3">
                <button
                  onClick={() => setShowClearConfirm(false)}
                  className="flex-1 bg-gray-100 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-200 text-sm"
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    setShowClearConfirm(false);
                    onClear();
                    onClose();
                  }}
                  className="flex-1 bg-red-500 text-white py-2 px-4 rounded-lg hover:bg-red-600 text-sm"
                >
                  Clear Profile
                </button>
              </div>
            </div>
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
  const [personalProfile, setPersonalProfile] = useState<PersonalProfile | null>(null);
  const [showAnalysisModal, setShowAnalysisModal] = useState(false);
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
    const historyStr = localStorage.getItem('post_edit_analysis_history');
    if (!historyStr) {
      alert('No analysis history found. Please analyze some translations first.');
      return;
    }

    const history: StoredAnalysis[] = JSON.parse(historyStr);
    if (history.length === 0) {
      alert('No analysis history found. Please analyze some translations first.');
      return;
    }

    // Aggregate patterns from all analyses (exploratory approach)
    const allPatterns: string[] = [];
    const allPriorities: string[] = [];
    const allMotivations: string[] = [];
    const allImplications: string[] = [];

    for (const analysis of history) {
      const result = analysis.analysis_result;

      // Collect emerging patterns
      if (result.emerging_patterns) {
        allPatterns.push(result.emerging_patterns);
      }

      // Collect user priorities
      if (result.user_priorities) {
        allPriorities.push(result.user_priorities);
      }

      // Collect change motivations
      for (const change of result.observed_changes) {
        if (change.possible_motivation) {
          allMotivations.push(change.possible_motivation);
        }
      }

      // Collect implications
      if (result.implications) {
        allImplications.push(result.implications);
      }
    }

    // Keep unique patterns
    const uniquePatterns = [...new Set(allPatterns)].slice(0, 10);
    const uniquePriorities = [...new Set(allPriorities)].slice(0, 10);
    const uniqueMotivations = [...new Set(allMotivations)].slice(0, 15);

    // Create summary
    let summary = `Based on ${history.length} exploratory analyses: `;
    if (uniquePatterns.length > 0) {
      summary += `Observed patterns include: ${uniquePatterns[0]}. `;
    }
    if (uniquePriorities.length > 0) {
      summary += `User priorities: ${uniquePriorities[0]}. `;
    }
    if (allImplications.length > 0) {
      summary += `Implications: ${allImplications[0]}`;
    }

    const newProfile: PersonalProfile = {
      observed_patterns: uniquePatterns,
      user_priorities: uniquePriorities,
      change_motivations: uniqueMotivations,
      profile_summary: summary.trim(),
      analysis_count: history.length,
      last_updated: new Date().toISOString(),
      is_active: true
    };

    setPersonalProfile(newProfile);
    localStorage.setItem('personal_profile', JSON.stringify(newProfile));
    alert('Profile built successfully!');
  };

  const clearProfile = () => {
    // Clear localStorage
    localStorage.removeItem('personal_profile');
    localStorage.removeItem('post_edit_analysis_history');
    // Reset state
    setPersonalProfile(null);
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
      // Auto-use profile if available
      const shouldUseProfile = personalProfile !== null && personalProfile.analysis_count > 0;

      const response = await fetch(`${API_URL}/translate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: sourceText.trim(),
          source_lang: sourceLang,
          target_lang: targetLang,
          use_profile: shouldUseProfile,
          profile_data: shouldUseProfile ? personalProfile : null
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

  const handleAnalysisComplete = (result: PostEditAnalysisResult) => {
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
            Personalized Translator
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
              onClick={() => setShowAnalysisModal(true)}
              className="flex items-center space-x-2 bg-gradient-to-r from-purple-500 to-indigo-600 text-white px-4 py-2 rounded-lg hover:from-purple-600 hover:to-indigo-700 transition-colors"
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <span>Analyze</span>
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
                <span className="text-xs text-purple-600 font-medium">
                  Personalized
                </span>
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
                      setShowAnalysisModal(true);
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
      </main>

      {/* Modals */}
      {showAnalysisModal && (
        <AnalysisModal
          onClose={() => setShowAnalysisModal(false)}
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
          onClear={clearProfile}
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
