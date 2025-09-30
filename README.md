# Multilingual Communication Tool
The system is a real-time, bidirectional chat translation layer that allows users to define a "linguistic persona." This persona is then used to guide the translation model, aiming to preserve the user's unique identity and communication style across languages.

## Access Control
Access to the application is controlled through the backend URL. Only users who receive the randomly-generated tunnel URL from the researcher can access the system. The URL changes with each research session, providing natural access control.

## Research Version Deployment Architecture
- **Frontend**: Deployed on GitHub Pages at https://ariawantstokhs.github.io/multilingual-communication/
- **Backend**: Run locally and exposed via Cloudflare Tunnel (or ngrok)
- **Database**: MongoDB running locally

This setup allows researchers to run the backend on their local machine without needing a deployed server. Users access the deployed frontend and **enter the backend URL directly in the app**, so no frontend redeployment is needed when the tunnel URL changes.

## Setup Instructions for Researchers

### Prerequisites
1. Install MongoDB locally
2. Install Node.js and npm
3. Install Python 3.8+
4. Install Cloudflare Tunnel: `brew install cloudflared` (macOS)

### Step 1: Start MongoDB
```bash
# Start MongoDB locally
mongod
```

### Step 2: Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # macOS/Linux
   # venv\Scripts\activate  # Windows
   ```

3. Create a `.env` file in the backend directory with the following variables:
   ```env
   OPENAI_API_KEY=your-openai-api-key
   MONGODB_URL=mongodb://localhost:27017/global_chat
   CORS_ORIGINS=http://localhost:3000,http://localhost:3001,https://ariawantstokhs.github.io
   ```

4. Install dependencies and run the backend:
   ```bash
   pip install -r requirements.txt
   python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

### Step 3: Expose Backend with Cloudflare Tunnel
In a **new terminal window**, expose your local backend to the internet:

```bash
# Run the tunnel
cloudflared tunnel --url http://localhost:8000
```

You will see output like:
```
Your quick Tunnel has been created! Visit it at:
https://random-words-1234.trycloudflare.com
```

**Copy this URL** - you'll provide it to participants.

### Step 4: Share the URL with Participants
When participants visit the deployed frontend at https://ariawantstokhs.github.io/multilingual-communication/, they will see:

1. **Backend Configuration Screen** - They enter the tunnel URL you provide
2. **Login/Signup Screen** - They create an account or sign in
3. **Chat Interface** - They can start chatting

**No frontend redeployment needed!** The URL is entered by users directly in the app.

## Daily Research Workflow

### Starting a Research Session
```bash
# Terminal 1: Start MongoDB
mongod

# Terminal 2: Start Backend
cd backend
source venv/bin/activate
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Terminal 3: Expose Backend
cloudflared tunnel --url http://localhost:8000
```

**After starting the tunnel:**
1. Copy the tunnel URL (e.g., `https://random-words-1234.trycloudflare.com`)
2. Share it with participants
3. Participants enter this URL in the app's first screen

### Stopping a Research Session
1. Press `Ctrl+C` in each terminal to stop services
2. The Cloudflare Tunnel will automatically close
3. MongoDB will stop

**Note**: Each time you restart cloudflared, you get a new random URL. Simply share the new URL with participants - they can update it in the app by clearing their browser's localStorage or using a new browser/incognito window.

## Usage
1. When you first visit the application, you'll be prompted to enter the backend API URL
2. After entering the URL, you'll be taken to the sign up/sign in page
3. Once authenticated, you can use the multilingual chat interface

## Security Notes
- Access control is managed through the random tunnel URL - only share with authorized participants
- The tunnel URL changes with each session, providing natural session-based access control
- User authentication is handled via JWT tokens