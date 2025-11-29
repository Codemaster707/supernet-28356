import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  initializeApp,
  getApps,
} from 'firebase/app';
import {
  getAuth,
  signInAnonymously,
  onAuthStateChanged,
  signOut,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  reload
} from 'firebase/auth';
import {
  getFirestore,
  doc,
  setDoc,
  onSnapshot,
  getDoc
} from 'firebase/firestore';

import { 
  Shield, MessageSquare, User, Wrench, Notebook, Trash2, Send, LogOut, 
  Code, Globe, AlertTriangle, Key, Mail, CheckCircle, Loader2, ArrowRight 
} from 'lucide-react';

// ================ REAL PRODUCTION FIREBASE CONFIG ================
const firebaseConfig = {
  apiKey: "AIzaSyCsnkw7tjW8zNsoczBnz6Psk9ZFqh8Nq9s",
  authDomain: "supernet-28356.firebaseapp.com",
  projectId: "supernet-28356",
  storageBucket: "supernet-28356.firebasestorage.app",
  messagingSenderId: "78218707808",
  appId: "1:78218707808:web:d8a2d0cdc247f1d8f19405",
  measurementId: "G-S1X62XN6SD"
};

const APP_ID = "supernet-28356";

const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApps()[0];
const auth = getAuth(app);
const db = getFirestore(app);

// ================ Password Strength ================
const isPasswordStrong = (password) => ({
  isMinLength: password.length >= 12,
  hasMixedCase: /(?=.*[a-z])(?=.*[A-Z])/.test(password),
  hasNumber: /(?=.*\d)/.test(password),
  hasSymbol: /(?=.*[!@#$%^&*()_+={}\[\]:;"'<>,.?/\\|~`])/.test(password),
});

// ================ Modal Hook ================
const useModal = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [message, setMessage] = useState('');

  const show = (msg) => {
    setMessage(msg);
    setIsOpen(true);
  };

  const Modal = () => isOpen ? (
    <div className="fixed inset-0 z-[1000] flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="bg-gray-900 border border-blue-600 rounded-xl p-6 max-w-sm w-full shadow-2xl">
        <p className="text-white text-lg mb-4">{message}</p>
        <button onClick={() => setIsOpen(false)} className="w-full py-2 bg-blue-700 hover:bg-blue-600 text-white rounded-lg font-bold">
          OK
        </button>
      </div>
    </div>
  ) : null;

  return { showModal: show, Modal };
};

// ================ Password Reset Component ================
const PasswordReset = ({ setShowReset, showModal }) => {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [loading, setLoading] = useState(false);

  const send = async () => {
    if (!email) return;
    setLoading(true);
    try {
      await sendPasswordResetEmail(auth, email);
      setSent(true);
    } catch (e) {
      showModal('Failed to send reset link. Check email and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-lg mx-auto p-8 bg-gray-900 border border-blue-600 rounded-xl">
      <h3 className="text-2xl font-bold text-blue-400 mb-6 text-center">Reset Password</h3>
      {sent ? (
        <p className="text-green-400 text-center">Check your email for reset link!</p>
      ) : (
        <>
          <input type="email" placeholder="Your email" value={email} onChange={e => setEmail(e.target.value)} className="w-full p-3 bg-gray-800 border border-gray-700 rounded-lg text-white mb-4" />
          <button onClick={send} disabled={loading} className="w-full bg-blue-600 hover:bg-blue-700 py-3 rounded-lg font-bold flex justify-center items-center gap-2">
            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Mail className="w-5 h-5" />}
            Send Reset Link
          </button>
        </>
      )}
      <button onClick={() => setShowReset(false)} className="mt-4 text-sm text-gray-400 hover:text-white w-full text-center">
        Back to Login
      </button>
    </div>
  );
};

// ================ Main App ================
export default function App() {
  const [user, setUser] = useState(null);
  const [superID, setSuperID] = useState(null);
  const [loading, setLoading] = useState(true);
  const [messages, setMessages] = useState([]);
  const [userInput, setUserInput] = useState('');
  const [notes, setNotes] = useState([]);
  const [noteInput, setNoteInput] = useState('');

  // Auth state
  const [isLogin, setIsLogin] = useState(true);
  const [showReset, setShowReset] = useState(false);
  const [authEmail, setAuthEmail] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authUsername, setAuthUsername] = useState('');
  const [authError, setAuthError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);
  const [usernameStatus, setUsernameStatus] = useState({ available: false, message: '' });

  const { showModal, Modal } = useModal();
  const chatEndRef = useRef(null);

  // Load notes
  useEffect(() => {
    const saved = localStorage.getItem('supernet_notes');
    if (saved) setNotes(JSON.parse(saved));
  }, []);

  useEffect(() => {
    localStorage.setItem('supernet_notes', JSON.stringify(notes));
  }, [notes]);

  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  // Firebase Auth Listener
  useEffect(() => {
    const unsub = onAuthStateChanged(auth, (u) => {
      setUser(u);
      setLoading(false);

      if (u && !u.isAnonymous) {
        const profileRef = doc(db, `artifacts/${APP_ID}/users/${u.uid}/supernet_data/profile`);
        return onSnapshot(profileRef, (snap) => {
          setSuperID(snap.exists() ? snap.data() : null);
        });
      } else {
        setSuperID(null);
      }
    });
    return unsub;
  }, []);

  // Anonymous sign-in fallback
  useEffect(() => {
    if (!user && !loading) {
      signInAnonymously(auth).catch(() => {});
    }
  }, [user, loading]);

  // Username check
  const checkUsername = useCallback(async (name) => {
    if (!name || name.length < 3 || !/^[a-zA-Z0-9_]+$/.test(name)) {
      setUsernameStatus({ available: false, message: 'Invalid format' });
      return;
    }
    setUsernameStatus({ available: false, message: 'Checking...' });
    const ref = doc(db, `artifacts/${APP_ID}/public/data/uniqueUsernames`, name.toLowerCase());
    const snap = await getDoc(ref);
    setUsernameStatus({
      available: !snap.exists(),
      message: snap.exists() ? 'Taken' : 'Available!'
    });
  }, []);

  useEffect(() => {
    if (!isLogin && authUsername) {
      const t = setTimeout(() => checkUsername(authUsername), 500);
      return () => clearTimeout(t);
    }
  }, [authUsername, isLogin, checkUsername]);

  // Auth handler
  const handleAuth = async (e) => {
    e.preventDefault();
    setAuthError('');
    setAuthLoading(true);

    try {
      if (isLogin) {
        await signInWithEmailAndPassword(auth, authEmail, authPassword);
      } else {
        if (!usernameStatus.available || Object.values(isPasswordStrong(authPassword)).some(v => !v)) {
          throw new Error('Fix username or password');
        }
        const cred = await createUserWithEmailAndPassword(auth, authEmail, authPassword);
        const u = cred.user;

        const lower = authUsername.toLowerCase();
        await setDoc(doc(db, `artifacts/${APP_ID}/public/data/uniqueUsernames`, lower), {
          userId: u.uid,
          username: authUsername
        });

        await setDoc(doc(db, `artifacts/${APP_ID}/users/${u.uid}/supernet_data/profile`), {
          username: authUsername,
          email: authEmail,
          created: new Date().toISOString(),
          userId: u.uid
        });

        await sendEmailVerification(u);
        showModal('Registered! Check your email to verify.');
        setIsLogin(true);
      }
    } catch (err) {
      setAuthError(err.message.split('Firebase: ')[1]?.split(' (')[0] || 'Authentication failed');
    } finally {
      setAuthLoading(false);
    }
  };

  const signOutUser = async () => {
    await signOut(auth);
    showModal('Signed out successfully');
  };

  // Notes
  const addNote = (e) => {
    e.preventDefault();
    if (!noteInput.trim()) return;
    const note = { id: crypto.randomUUID(), content: noteInput.trim(), createdAt: new Date().toISOString() };
    setNotes(prev => [note, ...prev]);
    setNoteInput('');
  };

  const deleteNote = (id) => setNotes(prev => prev.filter(n => n.id !== id));

  // Assistant
  const generateResponse = (input) => {
    input = input.toLowerCase();
    if (input.includes('varad') || input.includes('who created')) return 'Supernet was created by Varad Wagh — the architect of digital civilization.';
    if (input.includes('id')) return 'Your Super ID is your permanent identity across the entire Supernet network.';
    if (input.includes('note')) return 'Your notes are stored privately in your browser — only you can see them.';
    if (input.includes('future')) return 'The future is decentralized, real-time, and identity-first. Welcome to it.';
    return "I'm the Supernet Assistant. Ask me about Varad, Super ID, notes, or the future.";
  };

  const sendMessage = (e) => {
    e.preventDefault();
    if (!userInput.trim()) return;
    setMessages(m => [...m, { text: userInput, sender: 'user' }]);
    setTimeout(() => {
      setMessages(m => [...m, { text: generateResponse(userInput), sender: 'bot' }]);
    }, 600);
    setUserInput('');
  };

  const scrollTo = (id) => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' });

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-900 text-blue-400">
        <Loader2 className="w-16 h-16 animate-spin mr-4" />
        <p className="text-2xl">Connecting to Supernet...</p>
      </div>
    );
  }

  const ButtonStyle = "bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-8 rounded-full transition shadow-lg";
  const InputStyle = "w-full p-3 bg-gray-800 border border-blue-800 rounded-lg text-white focus:ring-2 focus:ring-blue-500 focus:outline-none";

  return (
    <div className="min-h-screen bg-gray-900 text-white selection:bg-blue-600">
      <Modal />

      {/* Header */}
      <header className="sticky top-0 z-50 bg-gray-900/95 backdrop-blur border-b border-blue-900">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
          <h1 className="text-3xl font-extrabold text-blue-400">Supernet</h1>
          {user && !user.isAnonymous ? (
            <button onClick={signOutUser} className="flex items-center gap-2 text-red-400 border border-red-500 px-5 py-2 rounded-full hover:bg-red-900/30">
              <LogOut className="w-4 h-4" /> Sign Out
            </button>
          ) : (
            <button onClick={() => scrollTo('id')} className="bg-blue-600 hover:bg-blue-700 px-6 py-2 rounded-full flex items-center gap-2">
              <User className="w-5 h-5" /> Connect ID
            </button>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-16 space-y-32">

        {/* Hero */}
        <section id="home" className="text-center py-20">
          <Shield className="w-20 h-20 text-blue-400 mx-auto mb-8" />
          <h2 className="text-6xl font-extrabold bg-gradient-to-r from-blue-400 to-green-400 bg-clip-text text-transparent">
            The Digital Civilization is Here.
          </h2>
          <div className="mt-12">
            <button onClick={() => scrollTo('id')} className={ButtonStyle + " text-lg"}>
              Get Your Super ID <ArrowRight className="inline ml-2" />
            </button>
          </div>
        </section>

        {/* Super ID */}
        <section id="id" className="py-20">
          <div className="text-center mb-12">
            <User className="w-16 h-16 text-blue-400 mx-auto mb-4" />
            <h3 className="text-5xl font-bold text-blue-400">Your Super ID</h3>
          </div>

          <div className="flex justify-center">
            {user && !user.isAnonymous ? (
              <div className="bg-gray-800 border border-blue-600 rounded-xl p-10 max-w-md w-full text-center">
                <h4 className="text-4xl font-bold text-green-400 mb-6">Welcome, @{superID?.username}!</h4>
                <p className="text-gray-300 mb-4">Email: {user.email}</p>
                <p className={user.emailVerified ? "text-green-400" : "text-yellow-400"}>
                  {user.emailVerified ? 'Verified' : 'Verification pending'}
                </p>
                <button onClick={signOutUser} className="mt-8 w-full bg-red-600 hover:bg-red-700 py-3 rounded-lg font-bold">
                  Sign Out
                </button>
              </div>
            ) : showReset ? (
              <PasswordReset setShowReset={setShowReset} showModal={showModal} />
            ) : (
              <form onSubmit={handleAuth} className="bg-gray-800 border border-blue-600 rounded-xl p-10 max-w-md w-full space-y-6">
                <h3 className="text-3xl font-bold text-blue-400 text-center">
                  {isLogin ? 'SuperID Login' : 'Create SuperID'}
                </h3>
                {authError && <p className="text-red-400 text-center bg-red-900/30 p-3 rounded">{authError}</p>}
                <input type="email" placeholder="Email" value={authEmail} onChange={e => setAuthEmail(e.target.value)} className={InputStyle} required />
                {!isLogin && (
                  <>
                    <input type="text" placeholder="Username" value={authUsername} onChange={e => setAuthUsername(e.target.value)} className={InputStyle} required />
                    <p className={`text-sm ${usernameStatus.available ? 'text-green-400' : 'text-yellow-400'}`}>{usernameStatus.message}</p>
                  </>
                )}
                <input type="password" placeholder="Password (12+ chars, mixed)" value={authPassword} onChange={e => setAuthPassword(e.target.value)} className={InputStyle} required />
                {!isLogin && (
                  <div className="text-xs space-y-1 text-left">
                    {Object.entries(isPasswordStrong(authPassword)).map(([k, v]) => (
                      <div key={k} className={v ? 'text-green-400' : 'text-red-400'}>
                        {k === 'isMinLength' && '12+ characters'}
                        {k === 'hasMixedCase' && 'Upper & lower case'}
                        {k === 'hasNumber' && 'Has number'}
                        {k === 'hasSymbol' && 'Has symbol'}
                      </div>
                    ))}
                  </div>
                )}
                <button type="submit" disabled={authLoading} className="w-full bg-blue-600 hover:bg-blue-700 py-4 rounded-lg font-bold text-lg">
                  {authLoading ? 'Loading...' : (isLogin ? 'Login' : 'Register')}
                </button>
                <div className="text-center text-sm">
                  {isLogin ? (
                    <>
                      No account? <button type="button" onClick={() => setIsLogin(false)} className="text-blue-400 underline">Register</button> | 
                      <button type="button" onClick={() => setShowReset(true)} className="text-gray-400 underline ml-2">Forgot?</button>
                    </>
                  ) : (
                    <button type="button" onClick={() => setIsLogin(true)} className="text-blue-400 underline">Login</button>
                  )}
                </div>
              </form>
            )}
          </div>
        </section>

        {/* Assistant */}
        <section id="assistant" className="py-20">
          <div className="text-center mb-12">
            <MessageSquare className="w-16 h-16 text-green-400 mx-auto mb-4" />
            <h3 className="text-5xl font-bold text-green-400">Supernet Assistant</h3>
          </div>
          <div className="max-w-4xl mx-auto bg-gray-800 border border-green-800 rounded-xl overflow-hidden shadow-2xl h-96 flex flex-col">
            <div className="flex-1 p-6 overflow-y-auto space-y-4">
              {messages.length === 0 && <p className="text-center text-gray-500">Ask me anything...</p>}
              {messages.map((m, i) => (
                <div key={i} className={m.sender === 'user' ? 'text-right' : 'text-left'}>
                  <div className={`inline-block p-4 rounded-xl max-w-xs ${m.sender === 'user' ? 'bg-blue-600' : 'bg-gray-700'}`}>
                    {m.text}
                  </div>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>
            <form onSubmit={sendMessage} className="p-4 border-t border-green-800 bg-gray-900 flex gap-3">
              <input type="text" placeholder="Message Assistant..." value={userInput} onChange={e => setUserInput(e.target.value)} className={InputStyle + " flex-1"} />
              <button type="submit" className="bg-green-600 hover:bg-green-700 p-3 rounded-full"><Send className="w-6 h-6" /></button>
            </form>
          </div>
        </section>

        {/* Notes */}
        <section id="notes" className="py-20">
          <div className="text-center mb-12">
            <Notebook className="w-16 h-16 text-yellow-400 mx-auto mb-4" />
            <h3 className="text-5xl font-bold text-yellow-400">Supernet Notes</h3>
          </div>
          <div className="max-w-4xl mx-auto">
            <form onSubmit={addNote} className="flex gap-4 mb-8">
              <input type="text" placeholder="New thought..." value={noteInput} onChange={e => setNoteInput(e.target.value)} className={InputStyle + " flex-1"} />
              <button type="submit" className="bg-yellow-600 hover:bg-yellow-700 px-8 py-3 rounded-lg font-bold">Save</button>
            </form>
            <div className="space-y-4">
              {notes.map(note => (
                <div key={note.id} className="bg-gray-800 p-6 rounded-lg border border-yellow-800/50 flex justify-between items-start">
                  <p>{note.content}</p>
                  <button onClick={() => deleteNote(note.id)} className="text-red-400 hover:text-red-500"><Trash2 className="w-5 h-5" /></button>
                </div>
              ))}
            </div>
          </div>
        </section>

      </main>

      <footer className="py-8 text-center text-gray-500 border-t border-gray-800">
        <p>© 2025 Supernet • Digital Civilization • App ID: {APP_ID}</p>
      </footer>
    </div>
  );
}
