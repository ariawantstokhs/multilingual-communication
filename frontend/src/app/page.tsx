'use client';
import { useState, useEffect, useRef } from 'react';
import io, { Socket } from 'socket.io-client';

// Types
interface User {
  username: string;
  preferred_language: 'en' | 'ko' | 'es' | 'ur';
  created_at?: string;
  last_login?: string;
}

interface AuthResponse {
  access_token: string;
  token_type: string;
  user: User;
}

interface Message {
  _id?: string;
  sender: string;
  timestamp: string;
  original_text: string;
  original_language: string;
  text_en: string;
  text_ko: string;
  text_es: string;
  text_ur: string;
}

// CTI Gap Analysis Types (Based on Personal-Enacted Identity Gap Scale - Jung & Hecht 2004)
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

interface GapAnalysisHistory {
  _id: string;
  username: string;
  mt_version: string;
  edited_version: string;
  analysis_result: GapAnalysisResult;
  created_at: string;
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

const LANGUAGES = {
  en: 'English',
  ko: '한국어',
  es: 'Español',
  ur: 'اردو'
} as const;

// Hardcoded API URL for localhost testing
const API_URL = 'http://localhost:8000';

// Lab Access Password Component
function LabAccessForm({ onAccessGranted }: { onAccessGranted: () => void }) {
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password.trim()) {
      setError('Please enter the lab access password');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_URL}/auth/verify-lab-access`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ password: password.trim() }),
      });

      let data: unknown = {};
      try { data = await response.json(); } catch { /* ignore non-JSON */ }

      if (!response.ok) {
        const detail =
          typeof data === 'object' && data !== null && 'detail' in data && typeof (data as { detail?: string }).detail === 'string'
            ? (data as { detail?: string }).detail
            : response.statusText || "Request failed";
        throw new Error(detail);
      }

      // Store lab access in localStorage for session persistence
      localStorage.setItem('lab_access_granted', 'true');
      onAccessGranted();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Network error — check that the API is running";
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-100 via-white to-purple-50">
      <div className="max-w-md w-full mx-4">
        <div className="bg-white rounded-2xl shadow-xl p-8 border border-purple-100">
          <div className="text-center mb-8">
            <div className="w-16 h-16 bg-gradient-to-br from-purple-500 to-purple-600 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-white">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke="currentColor" strokeWidth="2"/>
                <circle cx="12" cy="16" r="1" fill="currentColor"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4" stroke="currentColor" strokeWidth="2"/>
              </svg>
            </div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Lab Access Required</h1>
            <p className="text-gray-600">Please enter the lab access password to continue</p>
          </div>

          {error && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
              {error}
            </div>
          )}
          
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="lab-password" className="block text-sm font-medium text-gray-700 mb-2">
                Lab Access Password
              </label>
              <input
                id="lab-password"
                type="password"
                required
                className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 text-gray-700 placeholder-purple-300"
                placeholder="Enter lab access password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            
            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-gradient-to-r from-purple-500 to-purple-600 text-white font-semibold py-3 px-4 rounded-lg hover:from-purple-600 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 transform transition-all duration-200 hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
            >
              {isLoading ? (
                <div className="flex items-center justify-center">
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                  Verifying Access...
                </div>
              ) : (
                'Access Lab'
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

// Login Component
function LoginForm({ onLogin, onBackendError }: { onLogin: (user: User, token: string) => void; onBackendError: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [selectedLanguage, setSelectedLanguage] = useState<keyof typeof LANGUAGES>('en');
  const [isLogin, setIsLogin] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Please fill in all fields');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const endpoint = isLogin ? '/auth/login' : '/auth/register';
      const response = await fetch(`${API_URL}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: username.trim(),
          password,
          preferred_language: selectedLanguage
        }),
      });

      let data: unknown = {};
      try { data = await response.json(); } catch { /* ignore non-JSON */ }

      if (!response.ok) {
        const detail =
          typeof data === 'object' && data !== null && 'detail' in data && typeof (data as { detail?: string }).detail === 'string'
            ? (data as { detail?: string }).detail
            : response.statusText || "Request failed";
        throw new Error(detail);
      }

      if (isLogin) {
        const authData = data as AuthResponse;
        onLogin(authData.user, authData.access_token);
        return;
      }
  
      // After successful registration, log in automatically
      const loginRes = await fetch(`${API_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
  
      let loginData: unknown = {};
      try { loginData = await loginRes.json(); } catch { /* ignore non-JSON */ }
      if (!loginRes.ok) {
        const detail =
          typeof loginData === 'object' && loginData !== null && 'detail' in loginData && typeof (loginData as { detail?: string }).detail === 'string'
            ? (loginData as { detail?: string }).detail
            : "Registration successful but login failed";
        throw new Error(detail);
      }

      const authData = loginData as AuthResponse;
      onLogin(authData.user, authData.access_token);
    } catch (err) {
      // If it's a network error, the backend might have restarted with a new URL
      if (err instanceof Error && (err.message.includes('Failed to fetch') || err.message.includes('NetworkError'))) {
        setError('Cannot reach backend. The backend URL may have changed. Redirecting to URL setup...');
        setTimeout(() => {
          onBackendError();
        }, 2000);
        return;
      }

      const msg =
        err instanceof Error
          ? err.message
          : "Network error — please check with your researcher";
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-100 via-white to-purple-50">
      <div className="max-w-md w-full mx-4">
        <div className="bg-white rounded-2xl shadow-xl p-8 border border-purple-100">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Welcome to Global Chat</h1>
            <p className="text-gray-600">Connect with people around the world</p>
          </div>

          {/* Toggle between Login and Register */}
          <div className="flex mb-6 bg-gray-100 rounded-lg p-1">
            <button
              type="button"
              onClick={() => setIsLogin(true)}
              className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-all duration-200 ${
                isLogin
                  ? 'bg-white text-purple-600 shadow-sm'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => setIsLogin(false)}
              className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-all duration-200 ${
                !isLogin
                  ? 'bg-white text-purple-600 shadow-sm'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              Sign Up
            </button>
          </div>

          {error && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
              {error}
            </div>
          )}
          
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-2">
                Username
              </label>
              <input
                id="username"
                type="text"
                required
                className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 text-gray-700 placeholder-purple-300"
                placeholder="Enter your username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 text-gray-700 placeholder-purple-300"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            <div>
              <label htmlFor="language" className="block text-sm font-medium text-gray-700 mb-2">
                Preferred Language
              </label>
              <select
                id="language"
                value={selectedLanguage}
                onChange={(e) => setSelectedLanguage(e.target.value as keyof typeof LANGUAGES)}
                className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-200 text-gray-700"
              >
                {Object.entries(LANGUAGES).map(([code, name]) => (
                  <option key={code} value={code}>{name}</option>
                ))}
              </select>
            </div>
            
            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-gradient-to-r from-purple-500 to-purple-600 text-white font-semibold py-3 px-4 rounded-lg hover:from-purple-600 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 transform transition-all duration-200 hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
            >
              {isLoading ? (
                <div className="flex items-center justify-center">
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                  {isLogin ? 'Signing In...' : 'Creating Account...'}
                </div>
              ) : (
                isLogin ? 'Sign In' : 'Create Account'
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

// CTI Gap Analysis Modal Component
function GapAnalysisModal({ token, onClose, onAnalysisComplete }: { token: string; onClose: () => void; onAnalysisComplete?: () => void }) {
  const [mtVersion, setMtVersion] = useState('');
  const [editedVersion, setEditedVersion] = useState('');
  const [analysisResult, setAnalysisResult] = useState<GapAnalysisResult | null>(null);
  const [history, setHistory] = useState<GapAnalysisHistory[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState<'analyze' | 'history'>('analyze');

  useEffect(() => {
    if (activeTab === 'history') {
      fetchHistory();
    }
  }, [activeTab]);

  const fetchHistory = async () => {
    try {
      setIsLoadingHistory(true);
      const response = await fetch(`${API_URL}/analysis/history?limit=10`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!response.ok) throw new Error('Failed to fetch history');
      const data = await response.json();
      setHistory(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load history');
    } finally {
      setIsLoadingHistory(false);
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
      const response = await fetch(`${API_URL}/analysis/identity-gap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
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

      // Notify parent to rebuild profile after successful analysis
      if (onAnalysisComplete) {
        onAnalysisComplete();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const renderAnalysisResult = (result: GapAnalysisResult) => (
    <div className="space-y-6">
      {/* Summary */}
      <div className="bg-gradient-to-r from-purple-50 to-indigo-50 p-4 rounded-lg border border-purple-200">
        <h4 className="font-semibold text-purple-900 mb-2">Identity Gap Summary</h4>
        <p className="text-purple-800">{result.summary}</p>
      </div>

      {/* Factor 1: Inauthenticity - Where MT causes inauthentic expression */}
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

      {/* Factor 2: Authenticity - Where user restores authentic expression */}
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

        {/* Tabs */}
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
            History
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
                    placeholder="e.g., Can I ask about internship opportunities if possible?"
                    className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 text-gray-700"
                    rows={3}
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
                    placeholder="e.g., I was wondering if I might inquire about potential internship opportunities?"
                    className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 text-gray-700"
                    rows={3}
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
            {isLoadingHistory ? (
              <div className="text-center py-8">
                <div className="w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
              </div>
            ) : history.length === 0 ? (
              <p className="text-center text-gray-500 py-8">No analysis history yet. Start by analyzing your first translation!</p>
            ) : (
              <div className="space-y-6">
                {history.map((item) => (
                  <div key={item._id} className="border border-gray-200 rounded-lg p-4">
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

// Chat Interface Component
function ChatInterface({ user, token, onLogout, onBackendError }: { user: User; token: string; onLogout?: () => void; onBackendError: () => void }) {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [preferredLanguage, setPreferredLanguage] = useState<keyof typeof LANGUAGES>(user.preferred_language);
  const [isConnected, setIsConnected] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  const [showGapAnalysisModal, setShowGapAnalysisModal] = useState(false);
  const [personalProfile, setPersonalProfile] = useState<PersonalProfile | null>(null);
  const [isLoadingProfile, setIsLoadingProfile] = useState(false);
  const [isBuildingProfile, setIsBuildingProfile] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Fetch personal profile on mount
  useEffect(() => {
    const fetchPersonalProfile = async () => {
      try {
        setIsLoadingProfile(true);
        const response = await fetch(`${API_URL}/profile/personal`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.ok) {
          const profile = await response.json();
          if (profile.analysis_count > 0) {
            setPersonalProfile(profile);
          }
        }
      } catch (err) {
        console.error('Failed to fetch personal profile:', err);
      } finally {
        setIsLoadingProfile(false);
      }
    };
    fetchPersonalProfile();
  }, [token]);

  const buildProfile = async () => {
    try {
      setIsBuildingProfile(true);
      const response = await fetch(`${API_URL}/profile/build`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const profile = await response.json();
        setPersonalProfile(profile);
      } else {
        const error = await response.json();
        alert(error.detail || 'Failed to build profile');
      }
    } catch (err) {
      console.error('Failed to build profile:', err);
      alert('Failed to build profile');
    } finally {
      setIsBuildingProfile(false);
    }
  };

  const toggleProfileActive = async () => {
    if (!personalProfile) return;
    try {
      const response = await fetch(`${API_URL}/profile/toggle-active`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const result = await response.json();
        setPersonalProfile({ ...personalProfile, is_active: result.is_active });
      }
    } catch (err) {
      console.error('Failed to toggle profile:', err);
    }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    const newSocket = io(API_URL, {
      path: '/socket.io',
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });
    setSocket(newSocket);

    newSocket.on('connect', () => {
      setIsConnected(true);
      setConnectionError(false);
      newSocket.emit('authenticate', { token });
    });

    newSocket.on('disconnect', () => {
      setIsConnected(false);
      setIsAuthenticated(false);
    });

    newSocket.on('connect_error', () => {
      setConnectionError(true);
      // After multiple failed reconnection attempts, redirect to URL setup
      setTimeout(() => {
        if (!isConnected) {
          onBackendError();
        }
      }, 5000); // Give 5 seconds before redirecting
    });

    newSocket.on('auth_success', () => setIsAuthenticated(true));
    newSocket.on('auth_error', () => setIsAuthenticated(false));

    newSocket.on('message_history', (history: Message[]) => setMessages(history));
    newSocket.on('new_message', (m: Message) => setMessages(prev => [...prev, m]));

    return () => {
      newSocket.close();
    };
  }, [token, onBackendError]);
  
  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const sendMessage = async () => {
    if (newMessage.trim() && socket && isConnected && isAuthenticated) {
      socket.emit('send_message', {
        text: newMessage
      });
      setNewMessage('');
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const getMessageText = (message: Message): string => {
    const languageKey = `text_${preferredLanguage}` as keyof Message;
    return (message[languageKey] as string) || message.original_text;
  };

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Left Sidebar - Purple Design */}
      <div className="w-72 bg-gradient-to-b from-purple-300 via-purple-400 to-purple-500 flex flex-col relative">
        {/* Header Section */}
        <div className="p-6 pb-8">
          <h1 className="text-3xl font-bold text-gray-800 mb-2">Global Chat</h1>
          <div className="text-gray-700 text-lg font-medium"># general</div>
        </div>

        {/* Personal Profile Section */}
        <div className="mt-auto p-6 mb-3">
          {/* Personal Profile Card */}
          {personalProfile ? (
            <div className={`bg-white bg-opacity-90 rounded-lg p-4 border-2 ${personalProfile.is_active ? 'border-green-400' : 'border-gray-300'} mb-3`}>
              <div className="flex justify-between items-start mb-2">
                <h3 className="font-bold text-gray-800 text-sm">Personal Profile</h3>
                <button
                  onClick={toggleProfileActive}
                  className={`text-xs px-2 py-1 rounded-full font-medium ${
                    personalProfile.is_active
                      ? 'bg-green-500 text-white'
                      : 'bg-gray-300 text-gray-600'
                  }`}
                >
                  {personalProfile.is_active ? 'Active' : 'Inactive'}
                </button>
              </div>

              <div className="space-y-2 text-xs">
                {/* Factor 1: Common inauthenticity fixes */}
                {personalProfile.common_inauthenticity_fixes.length > 0 && (
                  <div>
                    <span className="font-medium text-gray-600">Factor 1 Fixes:</span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {personalProfile.common_inauthenticity_fixes.slice(0, 2).map((fix, i) => (
                        <span key={i} className="bg-red-100 text-red-700 px-1.5 py-0.5 rounded text-xs truncate max-w-full">
                          {fix.length > 30 ? fix.substring(0, 30) + '...' : fix}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {/* Factor 2: Common authenticity patterns */}
                {personalProfile.common_authenticity_patterns.length > 0 && (
                  <div>
                    <span className="font-medium text-gray-600">Factor 2 Patterns:</span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {personalProfile.common_authenticity_patterns.slice(0, 2).map((pattern, i) => (
                        <span key={i} className="bg-green-100 text-green-700 px-1.5 py-0.5 rounded text-xs truncate max-w-full">
                          {pattern.length > 30 ? pattern.substring(0, 30) + '...' : pattern}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {/* Scale item counts */}
                {Object.keys(personalProfile.authenticity_scale_items).length > 0 && (
                  <div>
                    <span className="font-medium text-gray-600">Top Scale Items:</span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {Object.entries(personalProfile.authenticity_scale_items)
                        .sort(([,a], [,b]) => b - a)
                        .slice(0, 3)
                        .map(([item, count], i) => (
                          <span key={i} className="bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded text-xs">
                            Item {item}: {count}x
                          </span>
                        ))}
                    </div>
                  </div>
                )}
                <div className="text-gray-500 mt-2 pt-2 border-t border-gray-200">
                  Built from {personalProfile.analysis_count} {personalProfile.analysis_count === 1 ? 'analysis' : 'analyses'}
                </div>
              </div>

              <button
                onClick={buildProfile}
                disabled={isBuildingProfile}
                className="w-full mt-3 bg-purple-500 text-white py-1.5 px-3 rounded text-xs font-medium hover:bg-purple-600 disabled:opacity-50"
              >
                {isBuildingProfile ? 'Rebuilding...' : 'Rebuild Profile'}
              </button>
            </div>
          ) : (
            <div className="bg-white bg-opacity-80 rounded-lg p-4 border border-gray-300 mb-3">
              <h3 className="font-bold text-gray-800 text-sm mb-2">Personal Profile</h3>
              <p className="text-xs text-gray-600 mb-3">
                No profile yet. Analyze your translations to build your communication identity profile.
              </p>
              <button
                onClick={buildProfile}
                disabled={isBuildingProfile || isLoadingProfile}
                className="w-full bg-purple-500 text-white py-2 px-3 rounded text-xs font-medium hover:bg-purple-600 disabled:opacity-50"
              >
                {isBuildingProfile ? 'Building...' : isLoadingProfile ? 'Loading...' : 'Build Profile'}
              </button>
            </div>
          )}

          {/* CTI Gap Analysis Button */}
          <button
            onClick={() => setShowGapAnalysisModal(true)}
            className="w-full bg-gradient-to-r from-indigo-500 to-purple-600 bg-opacity-80 hover:bg-opacity-90 rounded-lg p-3 border border-white border-opacity-20 text-white font-medium text-sm transition-all duration-200 flex items-center justify-between"
          >
            <span>Identity Gap Analysis</span>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
              <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </button>
        </div>

        {/* Language Selection */}
        <div className="p-6 pt-0 mb-5">
          <label className="block text-white text-xs font-normal mb-2">
            Display Language
          </label>
          <select
            value={preferredLanguage}
            onChange={(e) => setPreferredLanguage(e.target.value as keyof typeof LANGUAGES)}
            className="w-full p-3 bg-white bg-opacity-30 backdrop-blur-sm rounded-lg border border-white border-opacity-20 text-gray-800 placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-white focus:ring-opacity-50 focus:border-transparent transition-all duration-200"
          >
            {Object.entries(LANGUAGES).map(([code, name]) => (
              <option key={code} value={code} className="text-gray-800 bg-white">{name}</option>
            ))}
          </select>
          {/* User info */}
          <div className="flex items-center space-x-3 bg-white bg-opacity-20 backdrop-blur-sm rounded-lg p-3 border border-white border-opacity-20 mt-5">
            <div className="w-8 h-8 bg-white rounded-full flex items-center justify-center">
              <span className="text-purple-500 font-semibold text-sm">
                {user.username.charAt(0).toUpperCase()}
              </span>
            </div>
            <div className="flex-1">
              <div className="text-gray-800 font-medium text-sm">{user.username}</div>
              <div className="flex items-center space-x-1">
                <div className={`w-2 h-2 rounded-full ${
                  isConnected && isAuthenticated ? 'bg-green-400' : 
                  isConnected ? 'bg-yellow-400' : 'bg-red-400'
                }`}></div>
                <span className="text-gray-700 text-xs">
                  {isConnected && isAuthenticated ? 'Connected' : 
                   isConnected ? 'Authenticating...' : 'Disconnected'}
                </span>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              {onLogout && (
                <button
                  onClick={onLogout}
                  className="p-1 text-gray-600 hover:text-gray-800 hover:bg-white hover:bg-opacity-20 rounded transition-colors duration-200"
                  title="Logout"
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <polyline points="16,17 21,12 16,7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <line x1="21" y1="12" x2="9" y2="12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </button>
              )}
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="text-gray-700">
                <path d="M6 12L10 8L6 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
          </div>
        </div>
        </div>

        {/* User Info */}
        {/* <div className="mt-auto p-6 mb-15">
          <div className="flex items-center space-x-3 bg-white bg-opacity-20 backdrop-blur-sm rounded-lg p-3 border border-white border-opacity-20">
            <div className="w-8 h-8 bg-white rounded-full flex items-center justify-center">
              <span className="text-purple-500 font-semibold text-sm">
                {user.username.charAt(0).toUpperCase()}
              </span>
            </div>
            <div className="flex-1">
              <div className="text-gray-800 font-medium text-sm">{user.username}</div>
              <div className="flex items-center space-x-1">
                <div className={`w-2 h-2 rounded-full ${
                  isConnected && isAuthenticated ? 'bg-green-400' : 
                  isConnected ? 'bg-yellow-400' : 'bg-red-400'
                }`}></div>
                <span className="text-gray-700 text-xs">
                  {isConnected && isAuthenticated ? 'Connected' : 
                   isConnected ? 'Authenticating...' : 'Disconnected'}
                </span>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              {onLogout && (
                <button
                  onClick={onLogout}
                  className="p-1 text-gray-600 hover:text-gray-800 hover:bg-white hover:bg-opacity-20 rounded transition-colors duration-200"
                  title="Logout"
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <polyline points="16,17 21,12 16,7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <line x1="21" y1="12" x2="9" y2="12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </button>
              )}
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="text-gray-700">
                <path d="M6 12L10 8L6 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
          </div>
        </div>
      </div> */}

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col bg-white">
        {/* Messages Area */}
        <div className="flex-1 p-6 overflow-y-auto">
          {messages.length === 0 ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center text-gray-400">
                <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-gray-400">
                    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </div>
                <p className="text-lg font-medium mb-2">Welcome to Global Chat</p>
                <p className="text-sm">Start a conversation with people around the world!</p>
              </div>
            </div>
          ) : (
            <div className="space-y-6">
              {messages.map((msg, index) => (
                <div key={msg._id || index} className="group">
                  <div className="flex items-center space-x-3 mb-2">
                    <div className="w-8 h-8 bg-gradient-to-br from-purple-400 to-purple-600 rounded-full flex items-center justify-center">
                      <span className="text-white font-semibold text-sm">
                        {msg.sender.charAt(0).toUpperCase()}
                      </span>
                    </div>
                    <span className="font-semibold text-gray-900">{msg.sender}</span>
                    <span className="text-xs text-gray-500">
                      {new Date(msg.timestamp).toLocaleTimeString()}
                    </span>
                    {msg.original_language !== preferredLanguage && (
                      <span className="text-xs bg-purple-100 text-purple-700 px-2 py-1 rounded-full font-medium">
                        Translated from {LANGUAGES[msg.original_language as keyof typeof LANGUAGES]}
                      </span>
                    )}
                  </div>
                  <div className="ml-11 text-gray-800 leading-relaxed">
                    {getMessageText(msg)}
                  </div>
                </div>
              ))}
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Message Input */}
        <div className="p-6 border-t border-gray-100">
          <div className="relative flex items-center space-x-4">
            <div className="flex-1 relative">
              <input
                type="text"
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Message #general"
                disabled={!isConnected || !isAuthenticated}
                className="w-full p-4 pr-12 bg-gray-50 rounded-xl border border-gray-200 text-gray-900 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent disabled:bg-gray-100 disabled:text-gray-400 transition-all duration-200"
              />
              <button 
                onClick={sendMessage}
                disabled={!isConnected || !isAuthenticated || !newMessage.trim()}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 p-2 text-purple-500 hover:bg-purple-50 rounded-lg transition-colors duration-200 disabled:text-gray-300 disabled:hover:bg-transparent"
              >
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" className="transform rotate-45">
                  <path d="M22 2L11 13" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M22 2L15 22L11 13L2 9L22 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </button>
            </div>
          </div>
          
          {!isConnected && (
            <div className="mt-3 flex items-center space-x-2 text-red-500 text-sm">
              <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
              <span>
                {connectionError
                  ? 'Cannot reach backend. Backend URL may have changed. Redirecting in 5s...'
                  : 'Reconnecting to server...'}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Gap Analysis Modal */}
      {showGapAnalysisModal && (
        <GapAnalysisModal
          token={token}
          onClose={() => setShowGapAnalysisModal(false)}
          onAnalysisComplete={buildProfile}
        />
      )}
    </div>
  );
}

// Main App Component
export default function Home() {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    setIsClient(true);

    // Check for stored token and user info
    const storedToken = localStorage.getItem('auth_token');
    const storedUser = localStorage.getItem('user_info');

    if (storedToken && storedUser) {
      try {
        setToken(storedToken);
        setUser(JSON.parse(storedUser));
      } catch (error) {
        console.error('Error parsing stored user data:', error);
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user_info');
      }
    }
  }, []);

  const handleLogin = (userData: User, authToken: string) => {
    setUser(userData);
    setToken(authToken);
    // Store in localStorage for persistence
    localStorage.setItem('auth_token', authToken);
    localStorage.setItem('user_info', JSON.stringify(userData));
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_info');
  };

  const handleBackendError = () => {
    // Reset user session on backend error
    setUser(null);
    setToken(null);
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_info');
  };

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

  // Step 1: Show login form if no user/token
  if (!user || !token) {
    return <LoginForm onLogin={handleLogin} onBackendError={handleBackendError} />;
  }

  // Step 2: Show chat interface if authenticated
  return <ChatInterface user={user} token={token} onLogout={handleLogout} onBackendError={handleBackendError} />;
}