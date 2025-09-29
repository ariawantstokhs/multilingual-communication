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

// Lab Access Password Component
function LabAccessForm({ onAccessGranted }: { onAccessGranted: () => void }) {
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

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

      let data: any = {};
      try { data = await response.json(); } catch { /* ignore non-JSON */ }

      if (!response.ok) {
        const detail = data?.detail || response.statusText || "Request failed";
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
function LoginForm({ onLogin }: { onLogin: (user: User, token: string) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [selectedLanguage, setSelectedLanguage] = useState<keyof typeof LANGUAGES>('en');
  const [isLogin, setIsLogin] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

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

      // If fetch failed due to CORS / network, res won't exist; but if we got here, parse JSON safely
      let data: any = {};
      try { data = await response.json(); } catch { /* ignore non-JSON */ }

      if (!response.ok) {
        // Show API error if present; otherwise hint at CORS/misconfig
        const detail = data?.detail || response.statusText || "Request failed";
        // Common “Failed to fetch” happens before this; but if we’re here and status is 0 or 4xx/5xx, show detail
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
  
      const loginData = await loginRes.json().catch(() => ({}));
      if (!loginRes.ok) {
        throw new Error(
          loginData?.detail || "Registration successful but login failed"
        );
      }
  
      const authData = loginData as AuthResponse;
      onLogin(authData.user, authData.access_token);
    } catch (err) {
      // If it’s a true network/CORS error, fetch throws before we get a response
      const msg =
        err instanceof Error
          ? err.message
          : "Network error — check that the API is running on http://localhost:8000 and CORS is set";
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
function ChatInterface({ user, token, onLogout }: { user: User; token: string; onLogout?: () => void }) {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [preferredLanguage, setPreferredLanguage] = useState<keyof typeof LANGUAGES>(user.preferred_language);
  const [isConnected, setIsConnected] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    const base = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    const newSocket = io(base, {
      path: '/socket.io',
      transports: ['websocket', 'polling'],
      reconnection: true,
    });
    setSocket(newSocket);
  
    newSocket.on('connect', () => {
      setIsConnected(true);
      newSocket.emit('authenticate', { token });
    });
  
    newSocket.on('disconnect', () => {
      setIsConnected(false);
      setIsAuthenticated(false);
    });
  
    newSocket.on('auth_success', () => setIsAuthenticated(true));
    newSocket.on('auth_error', () => setIsAuthenticated(false));
  
    newSocket.on('message_history', (history: Message[]) => setMessages(history));
    newSocket.on('new_message', (m: Message) => setMessages(prev => [...prev, m]));
  
    return () => {
      newSocket.close();
    };
  }, [token]);
  
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
              <span>Reconnecting to server...</span>
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
  const [hasLabAccess, setHasLabAccess] = useState(false);

  useEffect(() => {
    setIsClient(true);
    // Check for lab access first
    const labAccess = localStorage.getItem('lab_access_granted');
    if (labAccess === 'true') {
      setHasLabAccess(true);
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

  const handleLabAccessGranted = () => {
    setHasLabAccess(true);
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

  // Show lab access form if no lab access
  if (!hasLabAccess) {
    return <LabAccessForm onAccessGranted={handleLabAccessGranted} />;
  }

  // Show login form if no user/token
  if (!user || !token) {
    return <LoginForm onLogin={handleLogin} />;
  }

  // Show chat interface if authenticated
  return <ChatInterface user={user} token={token} onLogout={handleLogout} />;
}