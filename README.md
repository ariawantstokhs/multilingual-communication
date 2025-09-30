# Multilingual Communication Tool

Real-time chat with automatic translation. Users communicate in their preferred language while messages are automatically translated for others.

## Features
- Real-time multilingual chat (English, Korean, Spanish, Urdu)
- Automatic translation via OpenAI API
- JWT authentication & WebSocket communication
- User-controlled language preferences

## Architecture
- **Frontend**: GitHub Pages (https://ariawantstokhs.github.io/multilingual-communication/)
- **Backend**: Local FastAPI server exposed via Cloudflare Tunnel
- **Database**: Local MongoDB

**Access Control**: Participants receive a unique Cloudflare Tunnel URL that acts as the access key.

## Prerequisites
- MongoDB, Python 3.8+, Cloudflare Tunnel
- OpenAI API key (for translation)

### Install Dependencies
```bash
# macOS
brew install mongodb-community python cloudflared

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create .env file
cat > .env << EOF
OPENAI_API_KEY=your-openai-api-key-here
MONGODB_URL=mongodb://localhost:27017/global_chat
CORS_ORIGINS=https://ariawantstokhs.github.io
EOF
```

## Running the System

Start three terminals:

```bash
# Terminal 1: MongoDB
mongod

# Terminal 2: Backend
cd backend && source venv/bin/activate
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Terminal 3: Cloudflare Tunnel
cloudflared tunnel --url http://localhost:8000
```

Share the Cloudflare URL (e.g., `https://random-words-1234.trycloudflare.com`) with participants.

## User Flow
1. **Enter Backend URL** → Participant pastes the Cloudflare URL
2. **Sign Up/Sign In** → Create account or log in, select preferred language
3. **Chat** → Messages are auto-translated to each user's preferred language

## How Translation Works

1. User sends message in their preferred language
2. Backend translates to all supported languages via OpenAI API
3. All translations stored in MongoDB
4. Each user sees the message in their preferred language

**Message Structure:**
```javascript
{
  sender: "username",
  original_text: "Hello!",
  original_language: "en",
  text_en: "Hello!",
  text_ko: "안녕하세요!",
  text_es: "¡Hola!",
  text_ur: "ہیلو!"
}
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection errors | Check backend is running: `curl https://your-tunnel-url/health` |
| Tunnel URL changed | Share new URL; users clear storage: `localStorage.removeItem('api_url')` |
| MongoDB errors | Verify running: `ps aux \| grep mongod` |
| Translation fails | Check `OPENAI_API_KEY` in `.env` and API credits |

## Tech Stack
- **Frontend**: Next.js 15.5.2, TypeScript, TailwindCSS, Socket.io-client
- **Backend**: FastAPI, Python-socketio, MongoDB, JWT, OpenAI API
