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

const LANGUAGES = {
  en: 'English',
  ko: '한국어',
  es: 'Español',
  ur: 'اردو'
} as const;

// API URL Configuration Component
function ApiUrlForm({ onUrlSet }: { onUrlSet: (url: string) => void }) {
  const [apiUrl, setApiUrl] = useState('');
  const [error, setError] = useState('');
  const [isValidating, setIsValidating] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedUrl = apiUrl.trim();

    if (!trimmedUrl) {
      setError('Please enter the API URL');
      return;
    }

    // Basic URL validation
    try {
      new URL(trimmedUrl);
    } catch {
      setError('Please enter a valid URL (e.g., https://example.trycloudflare.com)');
      return;
    }

    // Validate that the backend is reachable
    setIsValidating(true);
    setError('');

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

      const response = await fetch(`${trimmedUrl}/health`, {
        method: 'GET',
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error('Backend responded but is not healthy');
      }

      // Success - save and proceed
      localStorage.setItem('api_url', trimmedUrl);
      onUrlSet(trimmedUrl);
    } catch (err) {
      if (err instanceof Error) {
        if (err.name === 'AbortError') {
          setError('Connection timeout. Please check the URL and try again.');
        } else if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
          setError('Cannot reach backend. Please verify the URL is correct and the backend is running.');
        } else {
          setError('Backend is not responding correctly. Please check with your researcher.');
        }
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setIsValidating(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-100 via-white to-blue-50">
      <div className="max-w-md w-full mx-4">
        <div className="bg-white rounded-2xl shadow-xl p-8 border border-blue-100">
          <div className="text-center mb-8">
            <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-blue-600 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-white">
                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <polyline points="3.27 6.96 12 12.01 20.73 6.96" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <line x1="12" y1="22.08" x2="12" y2="12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Backend Configuration</h1>
            <p className="text-gray-600">Enter the API URL provided by your researcher</p>
          </div>

          {error && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="api-url" className="block text-sm font-medium text-gray-700 mb-2">
                Backend API URL
              </label>
              <input
                id="api-url"
                type="text"
                required
                className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 text-gray-700 placeholder-blue-300"
                placeholder="https://example.trycloudflare.com"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
              />
              <p className="mt-2 text-xs text-gray-500">
                Ask your researcher for the Cloudflare Tunnel or ngrok URL
              </p>
            </div>

            <button
              type="submit"
              disabled={isValidating}
              className="w-full bg-gradient-to-r from-blue-500 to-blue-600 text-white font-semibold py-3 px-4 rounded-lg hover:from-blue-600 hover:to-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transform transition-all duration-200 hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
            >
              {isValidating ? (
                <div className="flex items-center justify-center">
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                  Validating Backend...
                </div>
              ) : (
                'Continue'
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

// Lab Access Password Component
function LabAccessForm({ onAccessGranted }: { onAccessGranted: () => void }) {
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const API_URL = typeof window !== 'undefined'
    ? (localStorage.getItem('api_url') || 'http://localhost:8000')
    : 'http://localhost:8000';

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

  const API_URL = typeof window !== 'undefined'
    ? (localStorage.getItem('api_url') || 'http://localhost:8000')
    : 'http://localhost:8000';

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

// Chat Interface Component
function ChatInterface({ user, token, onLogout, onBackendError }: { user: User; token: string; onLogout?: () => void; onBackendError: () => void }) {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [preferredLanguage, setPreferredLanguage] = useState<keyof typeof LANGUAGES>(user.preferred_language);
  const [isConnected, setIsConnected] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    const base = typeof window !== 'undefined'
      ? (localStorage.getItem('api_url') || 'http://localhost:8000')
      : 'http://localhost:8000';
    const newSocket = io(base, {
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
  }, [token, isConnected, onBackendError]);
  
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

        {/* Language Selection */}
        <div className="mt-auto p-6 mb-5">
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
    </div>
  );
}

// Main App Component
export default function Home() {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isClient, setIsClient] = useState(false);
  const [hasApiUrl, setHasApiUrl] = useState(false);

  useEffect(() => {
    setIsClient(true);

    // Check for API URL first
    const apiUrl = localStorage.getItem('api_url');
    if (apiUrl) {
      setHasApiUrl(true);
    }

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

  const handleApiUrlSet = (url: string) => {
    setHasApiUrl(true);
  };

  const handleBackendError = () => {
    // Reset everything and go back to URL input
    setHasApiUrl(false);
    setUser(null);
    setToken(null);
    localStorage.removeItem('api_url');
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

  // Step 1: Show API URL form if no API URL set
  if (!hasApiUrl) {
    return <ApiUrlForm onUrlSet={handleApiUrlSet} />;
  }

  // Step 2: Show login form if no user/token
  if (!user || !token) {
    return <LoginForm onLogin={handleLogin} onBackendError={handleBackendError} />;
  }

  // Step 3: Show chat interface if authenticated
  return <ChatInterface user={user} token={token} onLogout={handleLogout} onBackendError={handleBackendError} />;
}