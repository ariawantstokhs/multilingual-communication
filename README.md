# Multilingual Communication Tool
The system is a real-time, bidirectional chat translation layer that allows users to define a "linguistic persona." This persona is then used to guide the translation model, aiming to preserve the user's unique identity and communication style across languages.

## Lab Access Protection
This application includes lab access protection to ensure only authorized lab members can access the system. Before users can sign up or sign in, they must first enter the lab access password.

## Setup Instructions

### Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create a `.env` file in the backend directory with the following variables:
   ```env
   # Lab Access Password - Change this to your desired password
   LAB_ACCESS_PASSWORD=your_lab_password_here
   
   # JWT Secret Key - Change this in production
   SECRET_KEY=your-secret-key-change-this-in-production
   
   # MongoDB Connection String
   MONGODB_URL=mongodb://localhost:27017/global_chat
   
   # CORS Origins (comma-separated)
   CORS_ORIGINS=http://localhost:3000,http://localhost:3001
   ```

3. Install dependencies and run the backend:
   ```bash
   pip install -r requirements.txt
   python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

### Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies and run the frontend:
   ```bash
   npm install
   npm run dev
   ```

## Usage
1. When you first visit the application, you'll be prompted to enter the lab access password
2. After entering the correct password, you'll be taken to the sign up/sign in page
3. Once authenticated, you can use the multilingual chat interface

## Security Notes
- Change the `LAB_ACCESS_PASSWORD` in your `.env` file to a secure password
- Change the `SECRET_KEY` for JWT tokens in production
- The lab access password is stored in localStorage for the session duration