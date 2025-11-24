import { useState, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Send, Bot, User, Globe, Sparkles, AlertTriangle } from 'lucide-react'
import axios from 'axios'
import ReactMarkdown from 'react-markdown'

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  language?: string
  timestamp: Date
}

export default function ChatPage() {
  const [searchParams] = useSearchParams()
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [detectedLanguage, setDetectedLanguage] = useState('English')
  const [vulnerabilityContext, setVulnerabilityContext] = useState<any>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    // Check if we have vulnerability context from URL parameters
    const context = searchParams.get('context')
    const vulnId = searchParams.get('id')
    const title = searchParams.get('title')
    const severity = searchParams.get('severity')
    const cweId = searchParams.get('cwe')
    const description = searchParams.get('description')
    const filePath = searchParams.get('file')
    const lineNumber = searchParams.get('line')
    const codeSnippet = searchParams.get('code')

    if (context === 'vulnerability' && vulnId) {
      // Store vulnerability context
      const vulnContext = {
        id: vulnId,
        title: decodeURIComponent(title || ''),
        severity: severity || '',
        cweId: cweId || '',
        description: decodeURIComponent(description || ''),
        filePath: decodeURIComponent(filePath || ''),
        lineNumber: lineNumber || '',
        codeSnippet: codeSnippet ? decodeURIComponent(codeSnippet) : ''
      }
      setVulnerabilityContext(vulnContext)

      // Set initial message with vulnerability details
      setMessages([
        {
          id: '1',
          role: 'assistant',
          content: `# 🔒 Security Vulnerability Analysis

I've received details about a security vulnerability. I'm here to help you understand and fix it!

**Vulnerability:** ${vulnContext.title}
**Severity:** ${vulnContext.severity}
${vulnContext.cweId ? `**CWE ID:** ${vulnContext.cweId}` : ''}
${vulnContext.filePath ? `**File:** ${vulnContext.filePath}${vulnContext.lineNumber ? `:${vulnContext.lineNumber}` : ''}` : ''}

I can help you with:
- Understanding what this vulnerability means
- Step-by-step remediation instructions
- Secure code examples
- Best practices to prevent similar issues

Feel free to ask me anything about this vulnerability!`,
          timestamp: new Date(),
        },
      ])

      // Auto-populate the input field with a helpful question
      setInput(`How do I fix this ${vulnContext.title} vulnerability? Please provide step-by-step remediation guidance and secure code examples.`)
    } else {
      // Welcome message
      setMessages([
        {
          id: '1',
          role: 'assistant',
          content: `# 👋 Hello! I'm your AI Security Assistant

I can help you with:

- **Vulnerability Remediation**: Get step-by-step fixes for security issues
- **Security Best Practices**: Learn secure coding patterns
- **STRIDE Threat Analysis**: Understand threat modeling concepts
- **MITRE ATT&CK**: Explore attack techniques and defenses
- **Compliance Questions**: Ask about OWASP, CWE, and other standards

**I speak 90+ languages!** Just ask your question in any language, and I'll respond in the same language automatically.

Try asking:
- "How do I fix SQL injection vulnerabilities?"
- "Explain STRIDE threats in simple terms"
- "¿Cómo prevenir ataques XSS?" (Spanish)
- "SQLインジェクションを防ぐ方法は？" (Japanese)`,
          timestamp: new Date(),
        },
      ])
    }
  }, [searchParams])

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  const handleSend = async () => {
    if (!input.trim() || loading) return

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input,
      timestamp: new Date(),
    }

    setMessages((prev) => [...prev, userMessage])
    setInput('')
    setLoading(true)

    try {
      const token = localStorage.getItem('token')
      const response = await axios.post(
        '/api/chat',
        { message: input },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      )

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: response.data.response,
        language: response.data.language_name,
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, assistantMessage])
      setDetectedLanguage(response.data.language_name || 'English')
    } catch (error) {
      console.error('Chat error:', error)

      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: 'Sorry, I encountered an error. Please make sure the chatbot service is configured with an OPENAI_API_KEY.',
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, errorMessage])
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const sampleQuestions = [
    "How do I fix SQL injection in my code?",
    "Explain Cross-Site Scripting (XSS) vulnerabilities",
    "What is the STRIDE threat modeling framework?",
    "¿Cómo asegurar una aplicación web?",
    "Comment prévenir les attaques par injection?",
  ]

  return (
    <div className="h-[calc(100vh-8rem)] flex flex-col">
      {/* Header */}
      <div className="bg-gradient-to-r from-primary-600 to-primary-700 text-white p-6 rounded-t-lg">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center space-x-2">
              <Sparkles className="w-6 h-6" />
              <span>AI Security Assistant</span>
            </h1>
            <p className="text-primary-100 mt-1">Multilingual security guidance powered by Claude</p>
          </div>
          <div className="flex items-center space-x-2 bg-white/20 rounded-lg px-4 py-2">
            <Globe className="w-5 h-5" />
            <span className="text-sm">{detectedLanguage}</span>
          </div>
        </div>
      </div>

      {/* Vulnerability Context Card */}
      {vulnerabilityContext && (
        <div className="bg-gradient-to-r from-orange-50 to-red-50 border-l-4 border-orange-500 p-4 mx-6 mt-4 rounded-r-lg">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="w-6 h-6 text-orange-600 mt-1" />
            <div className="flex-1">
              <h3 className="text-sm font-bold text-orange-900 mb-2">Analyzing Vulnerability</h3>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <span className="font-medium text-orange-800">Title:</span>
                  <span className="text-orange-900 ml-2">{vulnerabilityContext.title}</span>
                </div>
                <div>
                  <span className="font-medium text-orange-800">Severity:</span>
                  <span className={`ml-2 px-2 py-0.5 rounded text-xs font-bold ${
                    vulnerabilityContext.severity === 'critical' ? 'bg-red-200 text-red-900' :
                    vulnerabilityContext.severity === 'high' ? 'bg-orange-200 text-orange-900' :
                    vulnerabilityContext.severity === 'medium' ? 'bg-yellow-200 text-yellow-900' :
                    'bg-blue-200 text-blue-900'
                  }`}>
                    {vulnerabilityContext.severity.toUpperCase()}
                  </span>
                </div>
                {vulnerabilityContext.cweId && (
                  <div>
                    <span className="font-medium text-orange-800">CWE:</span>
                    <span className="text-orange-900 ml-2">{vulnerabilityContext.cweId}</span>
                  </div>
                )}
                {vulnerabilityContext.filePath && (
                  <div className="col-span-2">
                    <span className="font-medium text-orange-800">Location:</span>
                    <code className="text-orange-900 ml-2 text-xs bg-orange-100 px-2 py-1 rounded">
                      {vulnerabilityContext.filePath}
                      {vulnerabilityContext.lineNumber && `:${vulnerabilityContext.lineNumber}`}
                    </code>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto bg-gray-50 p-6 space-y-6">
        {messages.map((message) => (
          <div
            key={message.id}
            className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-3xl flex space-x-3 ${
                message.role === 'user' ? 'flex-row-reverse space-x-reverse' : ''
              }`}
            >
              {/* Avatar */}
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 ${
                  message.role === 'user'
                    ? 'bg-primary-600 text-white'
                    : 'bg-gradient-to-br from-purple-500 to-pink-500 text-white'
                }`}
              >
                {message.role === 'user' ? (
                  <User className="w-5 h-5" />
                ) : (
                  <Bot className="w-5 h-5" />
                )}
              </div>

              {/* Message Content */}
              <div
                className={`flex-1 rounded-lg p-4 ${
                  message.role === 'user'
                    ? 'bg-primary-600 text-white'
                    : 'bg-white border border-gray-200'
                }`}
              >
                {message.role === 'user' ? (
                  <p className="whitespace-pre-wrap">{message.content}</p>
                ) : (
                  <div className="prose prose-sm max-w-none">
                    <ReactMarkdown>{message.content}</ReactMarkdown>
                  </div>
                )}

                <p className={`text-xs mt-2 ${message.role === 'user' ? 'text-primary-100' : 'text-gray-500'}`}>
                  {message.timestamp.toLocaleTimeString()}
                </p>
              </div>
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="flex space-x-3">
              <div className="w-10 h-10 rounded-full bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center">
                <Bot className="w-5 h-5 text-white" />
              </div>
              <div className="bg-white border border-gray-200 rounded-lg p-4">
                <div className="flex space-x-2">
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce delay-100"></div>
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce delay-200"></div>
                </div>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Sample Questions */}
      {messages.length <= 1 && (
        <div className="bg-white border-t border-gray-200 p-4">
          <p className="text-sm text-gray-600 mb-3">Try these example questions:</p>
          <div className="flex flex-wrap gap-2">
            {sampleQuestions.map((question, idx) => (
              <button
                key={idx}
                onClick={() => setInput(question)}
                className="text-sm bg-gray-100 hover:bg-gray-200 text-gray-700 px-3 py-2 rounded-lg transition"
              >
                {question}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <div className="bg-white border-t border-gray-200 p-4">
        <div className="max-w-4xl mx-auto flex items-end space-x-3">
          <div className="flex-1">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Ask a security question in any language..."
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none"
              rows={2}
              disabled={loading}
            />
          </div>
          <button
            onClick={handleSend}
            disabled={!input.trim() || loading}
            className="btn btn-primary p-3 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Send className="w-5 h-5" />
          </button>
        </div>

        <p className="text-xs text-gray-500 mt-2 text-center">
          Press Enter to send • Shift+Enter for new line
        </p>
      </div>
    </div>
  )
}
