// Test file with known vulnerabilities for enhanced scan testing

// Hardcoded secret
const password = "supersecret123";
const apiKey = "sk-1234567890abcdef";

// Weak crypto
const hash = md5(data);
const weakHash = sha1(input);

// Dangerous functions
const result = eval(userInput);
const func = new Function("return " + code);

// XSS vulnerabilities
element.innerHTML = userInput;
document.write(unsafeData);

// Insecure random
const token = Math.random().toString(36);

// SQL Injection pattern
const query = "SELECT * FROM users WHERE id = " + userId;

// Command injection pattern
const cmd = exec("ls " + userPath);

// Path traversal
const file = readFile("../../../etc/passwd");
