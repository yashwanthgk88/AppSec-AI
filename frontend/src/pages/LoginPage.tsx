import { useState } from 'react'
import { Shield, Lock, Mail } from 'lucide-react'
import axios from '../config/axios'
import { API_URL } from '../config/api'

interface LoginPageProps {
  onLogin: (token: string) => void
}

export default function LoginPage({ onLogin }: LoginPageProps) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isLogin, setIsLogin] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register'
      console.log('[Login] API_URL:', API_URL)
      console.log('[Login] axios.defaults.baseURL:', axios.defaults.baseURL)
      console.log('[Login] Full URL:', `${axios.defaults.baseURL}${endpoint}`)

      const response = await axios.post(endpoint, {
        username: email.split('@')[0],
        email,
        password,
      })

      onLogin(response.data.access_token)
    } catch (err: any) {
      console.error('[Login] Error:', err)
      console.error('[Login] Error response:', err.response)
      const errorMsg = err.response?.data?.detail || err.message || 'Authentication failed'
      setError(`${errorMsg} (URL: ${axios.defaults.baseURL})`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-900 via-primary-800 to-primary-700 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        {/* Logo and Title */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-white rounded-full mb-4">
            <Shield className="w-10 h-10 text-primary-600" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">SecureDev AI</h1>
          <p className="text-primary-200">AI-Enabled Application Security</p>
        </div>

        {/* Login/Register Card */}
        <div className="card p-8">
          <div className="flex border-b border-gray-200 mb-6">
            <button
              className={`flex-1 pb-3 text-center font-medium transition ${
                isLogin
                  ? 'text-primary-600 border-b-2 border-primary-600'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
              onClick={() => setIsLogin(true)}
            >
              Login
            </button>
            <button
              className={`flex-1 pb-3 text-center font-medium transition ${
                !isLogin
                  ? 'text-primary-600 border-b-2 border-primary-600'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
              onClick={() => setIsLogin(false)}
            >
              Register
            </button>
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-4">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="label">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="email"
                  className="input pl-10"
                  placeholder="Enter your email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
            </div>

            <div>
              <label className="label">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="password"
                  className="input pl-10"
                  placeholder="Enter password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              className="btn btn-primary w-full py-3"
              disabled={loading}
            >
              {loading ? 'Please wait...' : isLogin ? 'Login' : 'Register'}
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-gray-600">
            <p>Features included in this POC:</p>
            <ul className="mt-2 space-y-1 text-xs text-gray-500">
              <li>✓ Threat Modeling (DFD, STRIDE, MITRE)</li>
              <li>✓ SAST, SCA, Secret Scanning</li>
              <li>✓ Multilingual AI Chatbot</li>
              <li>✓ Excel, PDF, XML Reports</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}
