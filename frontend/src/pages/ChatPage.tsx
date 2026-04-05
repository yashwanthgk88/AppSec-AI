import { useState, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Send, Bot, User, Sparkles, AlertTriangle, BookOpen, MessageSquare, Shield, Code, Target, AlertCircle, Lock, Database, Globe, Server, FileText, ChevronRight, CheckCircle, Zap } from 'lucide-react'
import axios from 'axios'
import ReactMarkdown from 'react-markdown'

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
}

interface TrainingModule {
  id: string
  title: string
  description: string
  icon: React.ReactNode
  topics: TrainingTopic[]
}

interface TrainingTopic {
  id: string
  title: string
  description: string
  prompt: string
}

const trainingModules: TrainingModule[] = [
  {
    id: 'owasp-top-10',
    title: 'OWASP Top 10',
    description: 'Learn about the most critical web application security risks',
    icon: <Shield className="w-6 h-6" />,
    topics: [
      {
        id: 'a01-broken-access',
        title: 'A01: Broken Access Control',
        description: 'Restrictions on authenticated users are not properly enforced',
        prompt: 'Explain OWASP A01:2021 Broken Access Control in detail. Include: what it is, real-world examples, how attackers exploit it, the business impact, and step-by-step remediation strategies with code examples.'
      },
      {
        id: 'a02-crypto-failures',
        title: 'A02: Cryptographic Failures',
        description: 'Failures related to cryptography leading to sensitive data exposure',
        prompt: 'Explain OWASP A02:2021 Cryptographic Failures in detail. Include: what it is, common mistakes developers make, real-world breaches caused by this, and how to implement proper encryption with code examples.'
      },
      {
        id: 'a03-injection',
        title: 'A03: Injection',
        description: 'SQL, NoSQL, OS, and LDAP injection vulnerabilities',
        prompt: 'Explain OWASP A03:2021 Injection vulnerabilities in detail. Cover SQL injection, NoSQL injection, command injection, and LDAP injection. Include attack examples, impact, and remediation with parameterized queries and input validation code.'
      },
      {
        id: 'a04-insecure-design',
        title: 'A04: Insecure Design',
        description: 'Missing or ineffective security controls in design',
        prompt: 'Explain OWASP A04:2021 Insecure Design. Cover what constitutes insecure design vs implementation bugs, threat modeling importance, secure design principles, and how to build security into the SDLC from the start.'
      },
      {
        id: 'a05-security-misconfig',
        title: 'A05: Security Misconfiguration',
        description: 'Insecure default configurations and missing hardening',
        prompt: 'Explain OWASP A05:2021 Security Misconfiguration. Cover common misconfigurations in cloud, servers, frameworks, and applications. Include hardening checklists and automated scanning approaches.'
      },
      {
        id: 'a06-vulnerable-components',
        title: 'A06: Vulnerable Components',
        description: 'Using components with known vulnerabilities',
        prompt: 'Explain OWASP A06:2021 Vulnerable and Outdated Components. Cover SCA (Software Composition Analysis), dependency management, CVE monitoring, and strategies for keeping dependencies secure and updated.'
      },
      {
        id: 'a07-auth-failures',
        title: 'A07: Authentication Failures',
        description: 'Broken authentication and session management',
        prompt: 'Explain OWASP A07:2021 Identification and Authentication Failures. Cover credential stuffing, brute force attacks, session management flaws, MFA implementation, and secure authentication patterns.'
      },
      {
        id: 'a08-integrity-failures',
        title: 'A08: Software Integrity Failures',
        description: 'Code and infrastructure without integrity verification',
        prompt: 'Explain OWASP A08:2021 Software and Data Integrity Failures. Cover CI/CD pipeline security, supply chain attacks, insecure deserialization, and how to verify software integrity.'
      },
      {
        id: 'a09-logging-failures',
        title: 'A09: Security Logging Failures',
        description: 'Insufficient logging and monitoring',
        prompt: 'Explain OWASP A09:2021 Security Logging and Monitoring Failures. Cover what to log, how to detect attacks, SIEM integration, incident response, and compliance requirements for logging.'
      },
      {
        id: 'a10-ssrf',
        title: 'A10: Server-Side Request Forgery',
        description: 'SSRF attacks where servers make requests to unintended locations',
        prompt: 'Explain OWASP A10:2021 Server-Side Request Forgery (SSRF). Cover how SSRF works, attack scenarios including cloud metadata attacks, and defense strategies with code examples.'
      }
    ]
  },
  {
    id: 'common-vulnerabilities',
    title: 'Common Vulnerabilities',
    description: 'Deep dive into specific vulnerability types',
    icon: <AlertCircle className="w-6 h-6" />,
    topics: [
      {
        id: 'sql-injection',
        title: 'SQL Injection',
        description: 'Manipulating database queries through user input',
        prompt: 'Provide comprehensive training on SQL Injection. Cover: types (classic, blind, time-based, union-based), detection methods, exploitation techniques attackers use, and remediation with parameterized queries in multiple languages (Python, Java, Node.js, C#).'
      },
      {
        id: 'xss',
        title: 'Cross-Site Scripting (XSS)',
        description: 'Injecting malicious scripts into web pages',
        prompt: 'Provide comprehensive training on Cross-Site Scripting (XSS). Cover: reflected, stored, and DOM-based XSS, real attack scenarios, cookie theft, session hijacking, and prevention with output encoding, CSP, and sanitization.'
      },
      {
        id: 'csrf',
        title: 'Cross-Site Request Forgery',
        description: 'Forcing users to execute unwanted actions',
        prompt: 'Provide comprehensive training on Cross-Site Request Forgery (CSRF). Cover: how CSRF attacks work, same-origin policy, and prevention using CSRF tokens, SameSite cookies, and origin verification.'
      },
      {
        id: 'xxe',
        title: 'XML External Entities (XXE)',
        description: 'Exploiting XML parsers to access files or perform SSRF',
        prompt: 'Provide comprehensive training on XML External Entity (XXE) attacks. Cover: how XXE works, file disclosure, SSRF via XXE, denial of service, and how to configure XML parsers securely.'
      },
      {
        id: 'path-traversal',
        title: 'Path Traversal',
        description: 'Accessing files outside intended directories',
        prompt: 'Provide comprehensive training on Path Traversal (Directory Traversal) attacks. Cover: attack techniques, encoding bypass methods, and secure file handling practices with code examples.'
      },
      {
        id: 'insecure-deserialization',
        title: 'Insecure Deserialization',
        description: 'Exploiting object deserialization for code execution',
        prompt: 'Provide comprehensive training on Insecure Deserialization. Cover: how deserialization attacks work in Java, Python, PHP, and .NET, gadget chains, and secure alternatives to native serialization.'
      }
    ]
  },
  {
    id: 'secure-coding',
    title: 'Secure Coding Practices',
    description: 'Write secure code from the start',
    icon: <Code className="w-6 h-6" />,
    topics: [
      {
        id: 'input-validation',
        title: 'Input Validation',
        description: 'Properly validating and sanitizing all input',
        prompt: 'Provide comprehensive training on Input Validation. Cover: whitelist vs blacklist validation, validation on server vs client, regular expressions for validation, and handling different data types securely.'
      },
      {
        id: 'output-encoding',
        title: 'Output Encoding',
        description: 'Encoding output to prevent injection attacks',
        prompt: 'Provide comprehensive training on Output Encoding. Cover: HTML encoding, JavaScript encoding, URL encoding, CSS encoding, context-aware encoding, and using encoding libraries properly.'
      },
      {
        id: 'authentication-best-practices',
        title: 'Authentication Best Practices',
        description: 'Implementing secure authentication',
        prompt: 'Provide comprehensive training on Authentication Best Practices. Cover: password hashing (bcrypt, Argon2), secure session management, JWT security, OAuth 2.0 implementation, and MFA integration.'
      },
      {
        id: 'authorization-patterns',
        title: 'Authorization Patterns',
        description: 'Implementing proper access control',
        prompt: 'Provide comprehensive training on Authorization Patterns. Cover: RBAC, ABAC, implementing least privilege, authorization middleware patterns, and common authorization bypass vulnerabilities.'
      },
      {
        id: 'secure-api-design',
        title: 'Secure API Design',
        description: 'Building secure REST and GraphQL APIs',
        prompt: 'Provide comprehensive training on Secure API Design. Cover: API authentication (API keys, OAuth, JWT), rate limiting, input validation, CORS configuration, and API security testing.'
      },
      {
        id: 'secrets-management',
        title: 'Secrets Management',
        description: 'Handling sensitive configuration securely',
        prompt: 'Provide comprehensive training on Secrets Management. Cover: avoiding hardcoded secrets, using environment variables, secret vaults (HashiCorp Vault, AWS Secrets Manager), and secret rotation strategies.'
      }
    ]
  },
  {
    id: 'threat-modeling',
    title: 'Threat Modeling',
    description: 'Identify and mitigate threats systematically',
    icon: <Target className="w-6 h-6" />,
    topics: [
      {
        id: 'stride-methodology',
        title: 'STRIDE Methodology',
        description: 'Microsoft\'s threat classification model',
        prompt: 'Provide comprehensive training on STRIDE Threat Modeling. Cover each category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) with examples and mitigations for each.'
      },
      {
        id: 'dfd-creation',
        title: 'Data Flow Diagrams',
        description: 'Creating DFDs for threat analysis',
        prompt: 'Provide comprehensive training on creating Data Flow Diagrams (DFDs) for threat modeling. Cover: DFD elements (processes, data stores, data flows, external entities), trust boundaries, and DFD levels.'
      },
      {
        id: 'attack-trees',
        title: 'Attack Trees',
        description: 'Modeling attack scenarios hierarchically',
        prompt: 'Provide comprehensive training on Attack Trees for security analysis. Cover: creating attack trees, AND/OR nodes, calculating attack costs, and using attack trees for risk assessment.'
      },
      {
        id: 'threat-prioritization',
        title: 'Threat Prioritization',
        description: 'Ranking threats by risk and impact',
        prompt: 'Provide comprehensive training on Threat Prioritization. Cover: DREAD scoring, risk matrices, business impact analysis, and strategies for prioritizing security work.'
      }
    ]
  },
  {
    id: 'mitre-attack',
    title: 'MITRE ATT&CK Framework',
    description: 'Understand adversary tactics and techniques',
    icon: <Zap className="w-6 h-6" />,
    topics: [
      {
        id: 'attack-overview',
        title: 'ATT&CK Overview',
        description: 'Introduction to the MITRE ATT&CK framework',
        prompt: 'Provide comprehensive training on MITRE ATT&CK Framework. Cover: what it is, tactics vs techniques vs procedures, how to use the framework for threat intelligence and detection, and the different matrices (Enterprise, Mobile, ICS).'
      },
      {
        id: 'initial-access',
        title: 'Initial Access Techniques',
        description: 'How attackers gain initial foothold',
        prompt: 'Provide comprehensive training on MITRE ATT&CK Initial Access tactics. Cover: phishing, exploiting public-facing applications, supply chain compromise, and valid accounts. Include detection strategies.'
      },
      {
        id: 'persistence-techniques',
        title: 'Persistence Techniques',
        description: 'How attackers maintain access',
        prompt: 'Provide comprehensive training on MITRE ATT&CK Persistence techniques. Cover: scheduled tasks, startup items, web shells, implants, and account manipulation. Include detection and prevention strategies.'
      },
      {
        id: 'privilege-escalation',
        title: 'Privilege Escalation',
        description: 'How attackers gain higher privileges',
        prompt: 'Provide comprehensive training on MITRE ATT&CK Privilege Escalation. Cover: exploitation for privilege escalation, access token manipulation, sudo and setuid exploitation, and detection strategies.'
      }
    ]
  },
  {
    id: 'compliance',
    title: 'Security Compliance',
    description: 'Meet regulatory and compliance requirements',
    icon: <FileText className="w-6 h-6" />,
    topics: [
      {
        id: 'pci-dss',
        title: 'PCI DSS',
        description: 'Payment Card Industry Data Security Standard',
        prompt: 'Provide comprehensive training on PCI DSS compliance. Cover: the 12 requirements, scope definition, network segmentation, secure coding requirements, and common compliance gaps.'
      },
      {
        id: 'gdpr-security',
        title: 'GDPR Security Requirements',
        description: 'Technical security for GDPR compliance',
        prompt: 'Provide comprehensive training on GDPR Security Requirements. Cover: data protection by design, encryption requirements, access controls, breach notification, and security assessment requirements.'
      },
      {
        id: 'soc2',
        title: 'SOC 2 Trust Principles',
        description: 'Service Organization Control 2 framework',
        prompt: 'Provide comprehensive training on SOC 2 Trust Service Principles. Cover: Security, Availability, Processing Integrity, Confidentiality, and Privacy. Include common controls and evidence requirements.'
      },
      {
        id: 'hipaa',
        title: 'HIPAA Security',
        description: 'Healthcare data security requirements',
        prompt: 'Provide comprehensive training on HIPAA Security Rule requirements. Cover: administrative, physical, and technical safeguards, risk analysis requirements, and security incident procedures.'
      }
    ]
  }
]

export default function ChatPage() {
  const [searchParams] = useSearchParams()
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [vulnerabilityContext, setVulnerabilityContext] = useState<any>(null)
  const [activeTab, setActiveTab] = useState<'chat' | 'training'>('chat')
  const [selectedModule, setSelectedModule] = useState<string | null>(null)
  const [completedTopics, setCompletedTopics] = useState<Set<string>>(new Set())
  const messagesEndRef = useRef<HTMLDivElement>(null)

  // Load completed topics from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('completedTrainingTopics')
    if (saved) {
      setCompletedTopics(new Set(JSON.parse(saved)))
    }
  }, [])

  // Save completed topics to localStorage
  const markTopicCompleted = (topicId: string) => {
    const newCompleted = new Set(completedTopics)
    newCompleted.add(topicId)
    setCompletedTopics(newCompleted)
    localStorage.setItem('completedTrainingTopics', JSON.stringify([...newCompleted]))
  }

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
          content: `# Security Vulnerability Analysis

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
          content: `# Welcome to the AI Security Assistant

I can help you with:

- **Vulnerability Remediation**: Get step-by-step fixes for security issues
- **Security Best Practices**: Learn secure coding patterns
- **STRIDE Threat Analysis**: Understand threat modeling concepts
- **MITRE ATT&CK**: Explore attack techniques and defenses
- **Compliance Questions**: Ask about OWASP, CWE, and other standards

Try asking:
- "How do I fix SQL injection vulnerabilities?"
- "Explain STRIDE threats in simple terms"
- "What are the best practices for input validation?"
- "How do I prevent Cross-Site Scripting attacks?"

**Tip:** Check out the **Security Training** tab for structured learning modules!`,
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

  const handleSend = async (customMessage?: string) => {
    const messageToSend = customMessage || input
    if (!messageToSend.trim() || loading) return

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: messageToSend,
      timestamp: new Date(),
    }

    setMessages((prev) => [...prev, userMessage])
    setInput('')
    setLoading(true)

    // Switch to chat tab if on training
    if (activeTab === 'training') {
      setActiveTab('chat')
    }

    try {
      const token = localStorage.getItem('token')
      const response = await axios.post(
        '/api/chat',
        { message: messageToSend },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      )

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: response.data.response,
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, assistantMessage])
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

  const handleTopicClick = (topic: TrainingTopic) => {
    handleSend(topic.prompt)
    markTopicCompleted(topic.id)
  }

  const sampleQuestions = [
    "How do I fix SQL injection in my code?",
    "Explain Cross-Site Scripting (XSS) vulnerabilities",
    "What is the STRIDE threat modeling framework?",
    "What are the OWASP Top 10 vulnerabilities?",
    "How do I secure API endpoints?",
  ]

  const getModuleProgress = (module: TrainingModule) => {
    const completedCount = module.topics.filter(t => completedTopics.has(t.id)).length
    return {
      completed: completedCount,
      total: module.topics.length,
      percentage: Math.round((completedCount / module.topics.length) * 100)
    }
  }

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
            <p className="text-primary-100 mt-1">Security guidance and training powered by AI</p>
          </div>

          {/* Tab Switcher */}
          <div className="flex bg-white/20 rounded-lg p-1">
            <button
              onClick={() => setActiveTab('chat')}
              className={`flex items-center space-x-2 px-4 py-2 rounded-md transition ${
                activeTab === 'chat'
                  ? 'bg-white text-primary-700'
                  : 'text-white hover:bg-white/10'
              }`}
            >
              <MessageSquare className="w-4 h-4" />
              <span>Chat</span>
            </button>
            <button
              onClick={() => setActiveTab('training')}
              className={`flex items-center space-x-2 px-4 py-2 rounded-md transition ${
                activeTab === 'training'
                  ? 'bg-white text-primary-700'
                  : 'text-white hover:bg-white/10'
              }`}
            >
              <BookOpen className="w-4 h-4" />
              <span>Security Training</span>
            </button>
          </div>
        </div>
      </div>

      {activeTab === 'chat' ? (
        <>
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
                  placeholder="Ask a security question..."
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none"
                  rows={2}
                  disabled={loading}
                />
              </div>
              <button
                onClick={() => handleSend()}
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
        </>
      ) : (
        /* Training Tab */
        <div className="flex-1 overflow-y-auto bg-gray-50">
          {/* Training Header */}
          <div className="bg-gradient-to-r from-indigo-50 to-purple-50 border-b border-indigo-200 p-6">
            <div className="max-w-6xl mx-auto">
              <div className="flex items-center space-x-3 mb-2">
                <BookOpen className="w-8 h-8 text-indigo-600" />
                <h2 className="text-2xl font-bold text-gray-900">Security Awareness Training</h2>
              </div>
              <p className="text-gray-600">
                Interactive learning modules to master application security concepts. Click on any topic to get detailed explanations, examples, and remediation guidance.
              </p>

              {/* Overall Progress */}
              <div className="mt-4 bg-white rounded-lg p-4 border border-indigo-200">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">Overall Progress</span>
                  <span className="text-sm text-gray-500">
                    {completedTopics.size} / {trainingModules.reduce((acc, m) => acc + m.topics.length, 0)} topics completed
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-indigo-600 h-2 rounded-full transition-all"
                    style={{
                      width: `${(completedTopics.size / trainingModules.reduce((acc, m) => acc + m.topics.length, 0)) * 100}%`
                    }}
                  ></div>
                </div>
              </div>
            </div>
          </div>

          {/* Training Modules */}
          <div className="max-w-6xl mx-auto p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {trainingModules.map((module) => {
                const progress = getModuleProgress(module)
                const isSelected = selectedModule === module.id

                return (
                  <div
                    key={module.id}
                    className={`bg-white rounded-lg border-2 transition-all cursor-pointer ${
                      isSelected
                        ? 'border-indigo-500 shadow-lg'
                        : 'border-gray-200 hover:border-indigo-300 hover:shadow'
                    }`}
                    onClick={() => setSelectedModule(isSelected ? null : module.id)}
                  >
                    <div className="p-5">
                      <div className="flex items-start justify-between mb-3">
                        <div className={`p-3 rounded-lg ${
                          progress.percentage === 100
                            ? 'bg-green-100 text-green-600'
                            : 'bg-indigo-100 text-indigo-600'
                        }`}>
                          {module.icon}
                        </div>
                        {progress.percentage === 100 && (
                          <span className="text-green-600 flex items-center text-sm">
                            <CheckCircle className="w-4 h-4 mr-1" />
                            Complete
                          </span>
                        )}
                      </div>

                      <h3 className="text-lg font-semibold text-gray-900 mb-1">{module.title}</h3>
                      <p className="text-sm text-gray-600 mb-3">{module.description}</p>

                      {/* Module Progress */}
                      <div className="mb-3">
                        <div className="flex justify-between text-xs text-gray-500 mb-1">
                          <span>{progress.completed} / {progress.total} topics</span>
                          <span>{progress.percentage}%</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-1.5">
                          <div
                            className={`h-1.5 rounded-full transition-all ${
                              progress.percentage === 100 ? 'bg-green-500' : 'bg-indigo-500'
                            }`}
                            style={{ width: `${progress.percentage}%` }}
                          ></div>
                        </div>
                      </div>

                      <div className="flex items-center text-sm text-indigo-600">
                        <span>{isSelected ? 'Hide topics' : 'View topics'}</span>
                        <ChevronRight className={`w-4 h-4 ml-1 transition-transform ${isSelected ? 'rotate-90' : ''}`} />
                      </div>
                    </div>

                    {/* Expanded Topics */}
                    {isSelected && (
                      <div className="border-t border-gray-200 bg-gray-50 p-4">
                        <div className="space-y-2">
                          {module.topics.map((topic) => {
                            const isCompleted = completedTopics.has(topic.id)

                            return (
                              <button
                                key={topic.id}
                                onClick={(e) => {
                                  e.stopPropagation()
                                  handleTopicClick(topic)
                                }}
                                className={`w-full text-left p-3 rounded-lg border transition-all ${
                                  isCompleted
                                    ? 'bg-green-50 border-green-200 hover:bg-green-100'
                                    : 'bg-white border-gray-200 hover:border-indigo-300 hover:bg-indigo-50'
                                }`}
                              >
                                <div className="flex items-start justify-between">
                                  <div className="flex-1">
                                    <div className="flex items-center space-x-2">
                                      <h4 className="font-medium text-gray-900 text-sm">{topic.title}</h4>
                                      {isCompleted && (
                                        <CheckCircle className="w-4 h-4 text-green-500" />
                                      )}
                                    </div>
                                    <p className="text-xs text-gray-500 mt-1">{topic.description}</p>
                                  </div>
                                  <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0 mt-1" />
                                </div>
                              </button>
                            )
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>

            {/* Quick Start Section */}
            <div className="mt-8 bg-gradient-to-r from-purple-50 to-pink-50 rounded-lg border border-purple-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-3">Quick Start Learning Paths</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <button
                  onClick={() => {
                    const module = trainingModules.find(m => m.id === 'owasp-top-10')
                    if (module) handleTopicClick(module.topics[0])
                  }}
                  className="p-4 bg-white rounded-lg border border-purple-200 hover:border-purple-400 transition text-left"
                >
                  <div className="flex items-center space-x-3 mb-2">
                    <Shield className="w-5 h-5 text-purple-600" />
                    <span className="font-medium text-gray-900">New to Security?</span>
                  </div>
                  <p className="text-sm text-gray-600">Start with OWASP Top 10 basics</p>
                </button>

                <button
                  onClick={() => {
                    const module = trainingModules.find(m => m.id === 'secure-coding')
                    if (module) handleTopicClick(module.topics[0])
                  }}
                  className="p-4 bg-white rounded-lg border border-purple-200 hover:border-purple-400 transition text-left"
                >
                  <div className="flex items-center space-x-3 mb-2">
                    <Code className="w-5 h-5 text-purple-600" />
                    <span className="font-medium text-gray-900">Developer?</span>
                  </div>
                  <p className="text-sm text-gray-600">Learn secure coding practices</p>
                </button>

                <button
                  onClick={() => {
                    const module = trainingModules.find(m => m.id === 'threat-modeling')
                    if (module) handleTopicClick(module.topics[0])
                  }}
                  className="p-4 bg-white rounded-lg border border-purple-200 hover:border-purple-400 transition text-left"
                >
                  <div className="flex items-center space-x-3 mb-2">
                    <Target className="w-5 h-5 text-purple-600" />
                    <span className="font-medium text-gray-900">Security Architect?</span>
                  </div>
                  <p className="text-sm text-gray-600">Master threat modeling with STRIDE</p>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
