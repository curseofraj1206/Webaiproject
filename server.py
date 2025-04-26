from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import cohere
import os
from datetime import datetime, timedelta
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
import json
from dotenv import load_dotenv
from functools import wraps
import bcrypt
import random
import re

# Load environment variables
load_dotenv()

app = Flask(__name__)
# Configure CORS to allow requests from any origin during development
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type"]
    }
})

# Enable debug mode for development
app.debug = True

# Set host to 0.0.0.0 to make it accessible from other devices
HOST = '0.0.0.0'
PORT = 5000

# Routes to serve static HTML files
@app.route('/')
def serve_root():
    return send_file('index.html')

@app.route('/index.html')
def serve_index():
    return send_file('index.html')

@app.route('/register.html')
def serve_register():
    return send_file('register.html')

@app.route('/login.html')
def serve_login():
    return send_file('login.html')

# Initialize Cohere client with the provided API key
cohere_api_key = os.getenv('COHERE_API_KEY', 'NtMzD4Bogr7eNqgPFIP2GeKNQAO3H3fU1ylnPeZL')
co = cohere.Client(cohere_api_key)

# Secret key for JWT
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-here')  # Change this in production

# In-memory user storage (replace with a database in production)
users = {}
user_progress = {}

# Track used questions to avoid repeats
used_questions = set()

# Add difficulty levels for questions
difficulty_levels = {
    'easy': {
        'description': 'Basic concepts and fundamentals',
        'complexity_factor': 0.5
    },
    'medium': {
        'description': 'Intermediate concepts and practical applications',
        'complexity_factor': 1.0
    },
    'hard': {
        'description': 'Advanced concepts and system design',
        'complexity_factor': 1.5
    }
}

# Course-specific question templates
course_questions = {
    'computer_science': {
        'easy': [
            "What is {topic} and what are its basic components?",
            "Explain the fundamental concept of {topic} with a simple example.",
            "What are the main advantages of using {topic}?",
            "Describe a basic implementation of {topic}.",
            "How is {topic} used in everyday programming?"
        ],
        'medium': [
            "How would you implement {topic} to solve a real-world problem?",
            "Compare and contrast different approaches to implementing {topic}.",
            "Explain the trade-offs involved when using {topic}.",
            "How does {topic} impact system performance?",
            "What are the best practices when working with {topic}?"
        ],
        'hard': [
            "Design a scalable system that implements {topic} for high-traffic scenarios.",
            "How would you optimize {topic} for maximum efficiency in a distributed system?",
            "Explain advanced concepts of {topic} and their enterprise applications.",
            "What are the architectural considerations when implementing {topic} at scale?",
            "How would you handle edge cases and failure scenarios in {topic}?"
        ]
    },
    'mechanical': {
        'easy': [
            "What is {topic} and how does it work?",
            "Explain the basic principles of {topic}.",
            "What are the main components of {topic}?",
            "Describe a simple application of {topic}.",
            "How is {topic} used in basic mechanical systems?"
        ],
        'medium': [
            "How would you apply {topic} in a mechanical design?",
            "Compare different methods of implementing {topic}.",
            "What are the efficiency considerations for {topic}?",
            "How does {topic} affect system dynamics?",
            "What are the maintenance requirements for {topic}?"
        ],
        'hard': [
            "Design an advanced system utilizing {topic} for industrial applications.",
            "How would you optimize {topic} for maximum performance?",
            "Explain the complex interactions between {topic} and other systems.",
            "What are the critical design factors when scaling {topic}?",
            "How would you troubleshoot complex issues with {topic}?"
        ]
    },
    'electrical': {
        'easy': [
            "What is {topic} and what are its basic principles?",
            "Explain the fundamental concepts of {topic}.",
            "What are the main components in {topic}?",
            "Describe a basic circuit using {topic}.",
            "How is {topic} used in simple electrical systems?"
        ],
        'medium': [
            "How would you implement {topic} in a circuit design?",
            "Compare different approaches to {topic} implementation.",
            "What are the power considerations for {topic}?",
            "How does {topic} affect system efficiency?",
            "What are the safety considerations for {topic}?"
        ],
        'hard': [
            "Design a complex system utilizing {topic} for industrial applications.",
            "How would you optimize {topic} for power efficiency?",
            "Explain advanced applications of {topic} in modern electronics.",
            "What are the critical factors when scaling {topic}?",
            "How would you debug complex issues with {topic}?"
        ]
    },
    'civil': {
        'easy': [
            "What is {topic} and why is it important?",
            "Explain the basic principles of {topic}.",
            "What are the main components of {topic}?",
            "Describe a simple application of {topic}.",
            "How is {topic} used in basic construction?"
        ],
        'medium': [
            "How would you implement {topic} in a construction project?",
            "Compare different methods of applying {topic}.",
            "What are the safety considerations for {topic}?",
            "How does {topic} affect structural integrity?",
            "What are the maintenance requirements for {topic}?"
        ],
        'hard': [
            "Design a complex structure utilizing {topic} for large-scale projects.",
            "How would you optimize {topic} for maximum durability?",
            "Explain advanced applications of {topic} in modern construction.",
            "What are the critical factors when scaling {topic}?",
            "How would you troubleshoot issues with {topic} in existing structures?"
        ]
    },
    'chemical': {
        'easy': [
            "What is {topic} and how does it work?",
            "Explain the basic principles of {topic}.",
            "What are the main components in {topic}?",
            "Describe a simple process using {topic}.",
            "How is {topic} used in basic chemical processes?"
        ],
        'medium': [
            "How would you implement {topic} in process design?",
            "Compare different approaches to {topic} implementation.",
            "What are the safety considerations for {topic}?",
            "How does {topic} affect process efficiency?",
            "What are the control requirements for {topic}?"
        ],
        'hard': [
            "Design a complex process utilizing {topic} for industrial scale.",
            "How would you optimize {topic} for maximum yield?",
            "Explain advanced applications of {topic} in modern processes.",
            "What are the critical factors when scaling {topic}?",
            "How would you troubleshoot complex issues with {topic}?"
        ]
    },
    'biotech': {
        'easy': [
            "What is {topic} and how does it work?",
            "Explain the basic principles of {topic}.",
            "What are the main components of {topic}?",
            "Describe a simple application of {topic}.",
            "How is {topic} used in basic biotechnology?"
        ],
        'medium': [
            "How would you implement {topic} in bioprocess design?",
            "Compare different methods of applying {topic}.",
            "What are the safety considerations for {topic}?",
            "How does {topic} affect process efficiency?",
            "What are the control requirements for {topic}?"
        ],
        'hard': [
            "Design a complex process utilizing {topic} for industrial scale.",
            "How would you optimize {topic} for maximum yield?",
            "Explain advanced applications of {topic} in modern biotechnology.",
            "What are the critical factors when scaling {topic}?",
            "How would you troubleshoot complex issues with {topic}?"
        ]
    },
    'aerospace': {
        'easy': [
            "What is {topic} and how does it work?",
            "Explain the basic principles of {topic}.",
            "What are the main components of {topic}?",
            "Describe a simple application of {topic}.",
            "How is {topic} used in basic aerospace systems?"
        ],
        'medium': [
            "How would you implement {topic} in aerospace design?",
            "Compare different approaches to {topic} implementation.",
            "What are the safety considerations for {topic}?",
            "How does {topic} affect system performance?",
            "What are the maintenance requirements for {topic}?"
        ],
        'hard': [
            "Design a complex system utilizing {topic} for aerospace applications.",
            "How would you optimize {topic} for maximum performance?",
            "Explain advanced applications of {topic} in modern aerospace.",
            "What are the critical factors when scaling {topic}?",
            "How would you troubleshoot complex issues with {topic}?"
        ]
    }
}

# Course-specific topics
course_topics = {
    'computer_science': [
        "data structures", "algorithms", "object-oriented programming",
        "database management", "network protocols", "operating systems",
        "software architecture", "machine learning", "cybersecurity",
        "cloud computing", "distributed systems", "web development"
    ],
    'mechanical': [
        "thermodynamics", "fluid mechanics", "heat transfer",
        "machine design", "manufacturing processes", "robotics",
        "materials science", "dynamics", "control systems",
        "mechanical vibrations", "CAD/CAM", "mechatronics"
    ],
    'electrical': [
        "circuit analysis", "digital electronics", "power systems",
        "electromagnetic theory", "signal processing", "control systems",
        "microelectronics", "communication systems", "power electronics",
        "embedded systems", "VLSI design", "renewable energy"
    ],
    'civil': [
        "structural analysis", "geotechnical engineering", "transportation",
        "construction management", "environmental engineering", "hydraulics",
        "surveying", "concrete technology", "steel structures",
        "foundation engineering", "earthquake engineering", "urban planning"
    ],
    'chemical': [
        "mass transfer", "heat transfer", "fluid dynamics",
        "reaction kinetics", "process control", "thermodynamics",
        "separation processes", "plant design", "process safety",
        "biochemical engineering", "polymer science", "catalysis"
    ],
    'biotech': [
        "molecular biology", "genetic engineering", "fermentation",
        "bioprocess engineering", "cell culture", "enzyme technology",
        "bioinformatics", "immunology", "tissue engineering",
        "protein engineering", "genomics", "bioreactor design"
    ],
    'aerospace': [
        "aerodynamics", "propulsion systems", "aircraft structures",
        "flight mechanics", "avionics", "spacecraft design",
        "orbital mechanics", "composite materials", "flight control",
        "gas dynamics", "aircraft stability", "rocket propulsion"
    ]
}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Split 'Bearer <token>'
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        # Check query parameters if no Authorization header
        if not token and 'token' in request.args:
            token = request.args['token']
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Decode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            
            # Get user from decoded token
            email = data.get('email')
            if not email or email not in users:
                return jsonify({'error': 'Invalid user'}), 401
            
            current_user = users[email]
            
            # Initialize user progress if not exists
            if email not in user_progress:
                user_progress[email] = {
                    'totalQuestions': 0,
                    'totalScore': 0,
                    'bestScore': 0,
                    'history': [],
                    'questionsByCourse': {}
                }
            
            return f(current_user, *args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            print(f"Token validation error: {str(e)}")
            return jsonify({'error': f'Token validation error: {str(e)}'}), 401
    
    return decorated

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data received'}), 400

        email = data.get('email')
        password = data.get('password')
        
        print(f"Registration attempt for email: {email}")  # Debug logging
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        if not password:
            return jsonify({'error': 'Password is required'}), 400
            
        if email in users:
            return jsonify({'error': 'Email already registered'}), 400
            
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
            
        # Hash password with bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            
        users[email] = {
            'email': email,
            'password': hashed_password,
            'created_at': datetime.utcnow()
        }
        
        user_progress[email] = {
            'totalQuestions': 0,
            'totalScore': 0,
            'bestScore': 0,
            'history': [],
            'questionsByCourse': {}
        }
        
        print(f"User registered successfully: {email}")
        return jsonify({'message': 'Registration successful'}), 201
        
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    """Handle user login with improved error handling and token generation."""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data received'}), 400
            
        email = data.get('email')
        password = data.get('password')
        
        print(f"Login attempt for email: {email}")  # Debug logging
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
            
        user = users.get(email)
        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401
            
        # Check password with bcrypt
        if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return jsonify({'error': 'Invalid email or password'}), 401
            
        # Generate token with 24 hour expiry
        token = jwt.encode({
            'email': email,
            'exp': datetime.utcnow() + timedelta(hours=24),
            'iat': datetime.utcnow()  # Include issued at time
        }, app.config['SECRET_KEY'])
        
        # Initialize user progress if not exists
        if email not in user_progress:
            user_progress[email] = {
                'totalQuestions': 0,
                'totalScore': 0,
                'bestScore': 0,
                'history': [],
                'questionsByCourse': {}
            }
        
        print(f"Login successful for email: {email}")
        return jsonify({
            'token': token,
            'email': email,
            'message': 'Login successful'
        })
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def generate_question(course, difficulty='medium'):
    try:
        if course not in course_topics or difficulty not in difficulty_levels:
            return "Invalid course or difficulty level selected."

        # Get random topic and question template based on difficulty
        topic = random.choice(course_topics[course])
        template = random.choice(course_questions.get(course, {}).get(difficulty, course_questions[course]['medium']))
        
        # Generate the question
        question = template.format(topic=topic)
        
        # Add to used questions with difficulty level
        question_key = f"{course}:{difficulty}:{question}"
        if question_key in used_questions:
            return generate_question(course, difficulty)
            
        used_questions.add(question_key)
        return question
        
    except Exception as e:
        print(f"Error generating question: {str(e)}")
        return "Error generating question. Please try again."

def analyze_with_cohere(question, answer, course):
    """Analyze answer using Cohere's advanced models."""
    try:
        # First, get a detailed analysis using command model
        analysis_prompt = f"""You are an expert professor in {course} engineering conducting a technical interview.

Question: {question}
Student's Answer: {answer}

IMPORTANT: You must provide numerical scores for each category in EXACTLY this format: "Score: X/10" where X is a number between 0 and 10.

Analyze the answer in the following format:

1. Technical Accuracy
Score: [0-10]/10
- List all correct technical concepts mentioned
- Identify any technical errors or misconceptions
- Evaluate depth of technical understanding

2. Clarity
Score: [0-10]/10
- Organization and structure
- Communication effectiveness
- Logical flow

3. Practical Application
Score: [0-10]/10
- Real-world examples provided
- Industry relevance
- Implementation understanding

4. Technical Terminology
Score: [0-10]/10
- Appropriate use of technical terms
- Missing key terminology
- Professional communication

5. Detailed Feedback:
- Specific strengths
- Areas for improvement
- Critical missing concepts

6. Model Answer:
[Provide a comprehensive model answer]

7. Learning Resources:
- Online courses
- Technical documentation
- Research papers
- Practice problems
- Video tutorials"""

        # Get detailed analysis using the correct Cohere parameters
        analysis_response = co.generate(
            prompt=analysis_prompt,
            max_tokens=2500,
            temperature=0.2,
            frequency_penalty=0.5,
            presence_penalty=0.5,
            stop_sequences=["\n\n8."],
            return_likelihoods="NONE"
        )

        # Get a second opinion for verification
        verification_prompt = f"""Verify this {course} engineering interview answer:

Question: {question}
Answer: {answer}

IMPORTANT: You must provide numerical scores in EXACTLY this format: "Score: X/10" where X is a number between 0 and 10.

Rate each aspect:

1. Technical accuracy
Score: [0-10]/10
[Explanation]

2. Completeness
Score: [0-10]/10
[Explanation]

3. Practical understanding
Score: [0-10]/10
[Explanation]"""

        verification_response = co.generate(
            prompt=verification_prompt,
            max_tokens=1000,
            temperature=0.3,
            frequency_penalty=0.3,
            presence_penalty=0.3,
            stop_sequences=["\n\n4."],
            return_likelihoods="NONE"
        )

        # Combine and analyze both responses
        main_analysis = analysis_response.generations[0].text
        verification = verification_response.generations[0].text

        print("Main analysis response:", main_analysis)  # Debug logging
        print("Verification response:", verification)    # Debug logging

        return main_analysis, verification
        
    except Exception as e:
        print(f"Error in Cohere analysis: {str(e)}")
        return None, None

def extract_score(text, pattern):
    """Extract numerical score from text with improved accuracy."""
    try:
        print(f"Extracting score for pattern: {pattern}")  # Debug logging
        print(f"Text to search: {text}")                   # Debug logging
        
        # First try: Look for exact "Score: X/10" format
        matches = re.findall(r"Score:\s*(\d+(?:\.\d+)?)/10", text, re.IGNORECASE)
        if matches:
            score = float(matches[0])
            print(f"Found score using Score: X/10 pattern: {score}")  # Debug logging
            return max(0.0, min(10.0, score))
            
        # Second try: Look for X/10 format after the pattern
        safe_pattern = re.escape(pattern)
        matches = re.findall(rf"{safe_pattern}.*?(\d+(?:\.\d+)?)/10", text, re.IGNORECASE | re.DOTALL)
        if matches:
            score = float(matches[0])
            print(f"Found score using pattern with /10: {score}")  # Debug logging
            return max(0.0, min(10.0, score))
            
        # Third try: Look for numbers between 0-10 after score-related words
        matches = re.findall(r"(?:score|rating|points?):\s*(\d+(?:\.\d+)?)\s*(?:/10)?", text, re.IGNORECASE)
        if matches:
            score = float(matches[0])
            print(f"Found score using general number pattern: {score}")  # Debug logging
            return max(0.0, min(10.0, score))
            
        print("No score found, using default score")  # Debug logging
        return 5.0  # Default to middle score if no score found
        
    except Exception as e:
        print(f"Error extracting score: {str(e)}")  # Debug logging
        return 5.0  # Default to middle score on error

@app.route('/analyze', methods=['POST'])
@token_required
def analyze_answer(current_user):
    try:
        data = request.json
        answer = data.get('answer')
        question = data.get('question')
        course = data.get('course')
        timestamp = data.get('timestamp', datetime.utcnow().isoformat())
        
        if not answer or not question or not course:
            return jsonify({'error': 'Answer, question, and course are required'}), 400

        # Get AI analysis
        main_analysis, verification = analyze_with_cohere(question, answer, course)
        
        if not main_analysis:
            return jsonify({'error': 'Failed to analyze answer'}), 500

        # Extract components with improved accuracy
        feedback = {
            'accuracy': {
                'score': extract_score(main_analysis, "Technical Accuracy.*?Score") or 0.0,
                'facts': extract_list(main_analysis, "correct technical concepts", "technical errors") or 
                    ["No relevant technical concepts identified"]
            },
            'clarity': {
                'score': extract_score(verification, "Completeness.*?Score") or 0.0,
                'feedback': extract_text(main_analysis, "Detailed Feedback", "Model Answer") or 
                    "The answer needs improvement in structure and clarity."
            },
            'terminology': {
                'score': extract_score(main_analysis, "Technical Terminology.*?Score") or 0.0,
                'terms_used': extract_list(main_analysis, "Appropriate use of technical terms", "Missing key terminology") or [],
                'suggested_terms': extract_list(main_analysis, "Missing key terminology", "Professional communication") or 
                    ["Consider using appropriate technical terms"]
            },
            'practical_application': {
                'score': extract_score(main_analysis, "Practical Application.*?Score") or 0.0,
                'feedback': extract_text(main_analysis, "Real-world examples", "Technical Terminology") or 
                    "No practical applications were provided."
            },
            'improvements': extract_list(main_analysis, "Areas for improvement", "Model Answer") or [
                "Ensure your answer directly addresses the question",
                "Include relevant technical concepts",
                "Provide practical examples",
                "Use appropriate technical terminology"
            ],
            'model_answer': extract_text(main_analysis, "Model Answer:", "Learning Resources") or 
                "A proper answer should include technical concepts, practical examples, and appropriate terminology.",
            'resources': extract_resources(main_analysis) or get_learning_resources(course, extract_topic(question), 'medium')
        }

        # Calculate weighted score
        weights = {
            'accuracy': 0.4,
            'clarity': 0.2,
            'terminology': 0.2,
            'practical': 0.2
        }

        scores = {
            'accuracy': feedback['accuracy']['score'],
            'clarity': feedback['clarity']['score'],
            'terminology': feedback['terminology']['score'],
            'practical': feedback['practical_application']['score']
        }

        overall_score = sum(scores[k] * weights[k] for k in weights)

        # Update user progress
        email = current_user['email']
        if email not in user_progress:
            user_progress[email] = {
                'totalQuestions': 0,
                'totalScore': 0,
                'bestScore': 0,
                'history': [],
                'questionsByCourse': {}
            }

        # Create detailed history entry
        history_entry = {
            'question': question,
            'answer': answer,
            'score': overall_score,
            'course': course,
            'timestamp': timestamp,
            'feedback': {
                'accuracy': {
                    'score': feedback['accuracy']['score'],
                    'facts': feedback['accuracy']['facts']
                },
                'clarity': {
                    'score': feedback['clarity']['score'],
                    'feedback': feedback['clarity']['feedback']
                },
                'terminology': {
                    'score': feedback['terminology']['score'],
                    'terms_used': feedback['terminology']['terms_used'],
                    'suggested_terms': feedback['terminology']['suggested_terms']
                },
                'practical': {
                    'score': feedback['practical_application']['score'],
                    'feedback': feedback['practical_application']['feedback']
                }
            }
        }

        # Update progress
        user_progress[email]['history'].append(history_entry)
        user_progress[email]['history'] = user_progress[email]['history'][-50:]
        user_progress[email]['totalQuestions'] += 1
        user_progress[email]['totalScore'] += overall_score
        user_progress[email]['bestScore'] = max(user_progress[email]['bestScore'], overall_score)

        # Update course-specific stats
        if course not in user_progress[email]['questionsByCourse']:
            user_progress[email]['questionsByCourse'][course] = {
                'totalQuestions': 0,
                'totalScore': 0,
                'bestScore': 0
            }

        course_stats = user_progress[email]['questionsByCourse'][course]
        course_stats['totalQuestions'] += 1
        course_stats['totalScore'] += overall_score
        course_stats['bestScore'] = max(course_stats['bestScore'], overall_score)

        return jsonify(feedback)

    except Exception as e:
        print(f"Error in /analyze: {str(e)}")
        return jsonify({'error': str(e)}), 500

def extract_list(text, start_pattern, end_pattern):
    try:
        pattern = f"{start_pattern}(.*?){end_pattern}"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            items = re.findall(r'[-•*]\s*([^\n]+)', match.group(1))
            return [item.strip() for item in items if item.strip()]
        return []
    except:
        return []

def extract_text(text, start_pattern, end_pattern):
    try:
        pattern = f"{start_pattern}(.*?){end_pattern}"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return "No specific feedback provided."
    except:
        return "No specific feedback provided."

def get_learning_resources(course, topic, difficulty):
    """Generate relevant learning resources based on the course, topic, and difficulty."""
    resources = []
    
    # Documentation resources based on course and topic
    documentation_links = {
        'computer_science': {
            'data structures': ['https://www.geeksforgeeks.org/data-structures/', 
                              'https://leetcode.com/explore/learn/',
                              'https://www.programiz.com/dsa'],
            'algorithms': ['https://www.programiz.com/dsa',
                         'https://www.algorithmsilluminated.org/',
                         'https://algs4.cs.princeton.edu/home/'],
            'object-oriented programming': ['https://refactoring.guru/design-patterns',
                                         'https://sourcemaking.com/design_patterns',
                                         'https://www.tutorialspoint.com/object_oriented_programming/'],
            'database management': ['https://www.postgresql.org/docs/current/',
                                  'https://dev.mysql.com/doc/',
                                  'https://www.mongodb.com/docs/'],
            'network protocols': ['https://www.cloudflare.com/learning/',
                                'https://www.ietf.org/standards/',
                                'https://www.networksorcery.com/'],
            'operating systems': ['https://pages.cs.wisc.edu/~remzi/OSTEP/',
                                'https://www.ops-class.org/',
                                'https://www.kernel.org/doc/'],
            'software architecture': ['https://martinfowler.com/',
                                    'https://www.patterns.dev/',
                                    'https://microservices.io/'],
            'machine learning': ['https://scikit-learn.org/stable/user_guide.html',
                               'https://pytorch.org/tutorials/',
                               'https://www.tensorflow.org/learn'],
            'cybersecurity': ['https://www.hacksplaining.com/',
                            'https://owasp.org/www-project-top-ten/',
                            'https://www.sans.org/security-resources/'],
            'cloud computing': ['https://docs.aws.amazon.com/index.html',
                              'https://cloud.google.com/docs',
                              'https://learn.microsoft.com/en-us/azure/'],
            'distributed systems': ['https://martinfowler.com/articles/patterns-of-distributed-systems/',
                                  'https://sre.google/sre-book/table-of-contents/',
                                  'https://github.com/donnemartin/system-design-primer'],
            'web development': ['https://developer.mozilla.org/en-US/docs/Learn',
                              'https://web.dev/',
                              'https://www.w3schools.com/']
        },
        'mechanical': {
            'thermodynamics': ['https://www.engineeringtoolbox.com/thermodynamics-d_94.html',
                             'https://www.thermal-engineering.org/',
                             'https://ocw.mit.edu/courses/2-thermodynamics-and-kinetics/'],
            'fluid mechanics': ['https://www.engineeringtoolbox.com/fluid-mechanics-t_21.html',
                              'https://www.cfdsupport.com/OpenFOAM-Training-by-CFD-Support/node1.html',
                              'https://www.grc.nasa.gov/www/k-12/airplane/'],
            'heat transfer': ['https://www.thermal-engineering.org/thermal-engineering-fundamentals/',
                            'https://ocw.mit.edu/courses/2-51-intermediate-heat-and-mass-transfer-fall-2008/',
                            'https://www.engineeringtoolbox.com/heat-transfer-d_431.html'],
            'machine design': ['https://www.engineeringtoolbox.com/machine-design-d_53.html',
                             'https://www.khkgears.net/gear-knowledge/',
                             'https://www.machinedesign.com/learning-resources/']
        },
        'electrical': {
            'circuit analysis': ['https://www.allaboutcircuits.com/textbook/',
                               'https://ocw.mit.edu/courses/6-002-circuits-and-electronics-spring-2007/',
                               'https://www.electronics-tutorials.ws/'],
            'digital electronics': ['https://www.electronics-tutorials.ws/digital/',
                                  'https://www.nand2tetris.org/',
                                  'https://www.fpga4fun.com/'],
            'power systems': ['https://www.electrical4u.com/electrical-power-system/',
                            'https://ocw.mit.edu/courses/6-061-introduction-to-electric-power-systems-spring-2011/',
                            'https://www.powersystemsdesign.com/'],
            'electromagnetic theory': ['https://www.electronics-tutorials.ws/electromagnetics/',
                                    'https://ocw.mit.edu/courses/8-02-physics-ii-electricity-and-magnetism-spring-2007/',
                                    'https://www.feynmanlectures.caltech.edu/II_toc.html']
        }
    }

    # Add documentation resources
    if course in documentation_links and topic in documentation_links[course]:
        for doc_url in documentation_links[course][topic]:
            resources.append({
                'title': f"{topic.title()} Documentation and Guides",
                'url': doc_url,
                'type': 'documentation'
            })

    # Add video tutorials from multiple platforms
    video_platforms = {
        'coursera': 'https://www.coursera.org/search?query=',
        'edx': 'https://www.edx.org/search?q=',
        'udemy': 'https://www.udemy.com/courses/search/?q=',
        'youtube': 'https://www.youtube.com/results?search_query='
    }

    for platform, base_url in video_platforms.items():
        search_term = f"{course}+{topic}+{difficulty}+tutorial"
        resources.append({
            'title': f"{platform.title()} {topic.title()} Tutorials",
            'url': f"{base_url}{search_term.replace(' ', '+')}",
            'type': 'video'
        })

    # Add practice resources
    practice_platforms = {
        'computer_science': {
            'leetcode': 'https://leetcode.com/problemset/',
            'hackerrank': 'https://www.hackerrank.com/domains/',
            'codewars': 'https://www.codewars.com/kata/search/',
            'exercism': 'https://exercism.org/tracks/'
        },
        'mechanical': {
            'engineering_toolbox': 'https://www.engineeringtoolbox.com/practice-problems-d_405.html',
            'simscale': 'https://www.simscale.com/projects/',
            'grabcad': 'https://grabcad.com/library'
        },
        'electrical': {
            'circuitlab': 'https://www.circuitlab.com/editor/',
            'tinkercad': 'https://www.tinkercad.com/circuits',
            'falstad': 'https://www.falstad.com/circuit/'
        }
    }

    if course in practice_platforms:
        for platform, url in practice_platforms[course].items():
            resources.append({
                'title': f"Practice on {platform.title()}",
                'url': url,
                'type': 'practice'
            })

    # Add research papers and academic resources
    academic_resources = {
        'arxiv': f"https://arxiv.org/search/?query={topic.replace(' ', '+')}&searchtype=all",
        'google_scholar': f"https://scholar.google.com/scholar?q={topic.replace(' ', '+')}",
        'mit_opencourseware': f"https://ocw.mit.edu/search/?q={topic.replace(' ', '+')}"
    }

    for platform, url in academic_resources.items():
        resources.append({
            'title': f"{platform.replace('_', ' ').title()} Resources",
            'url': url,
            'type': 'academic'
        })

    # Add GitHub repositories with learning resources
    github_resources = {
        'computer_science': {
            'awesome_lists': f"https://github.com/search?q=awesome+{topic.replace(' ', '+')}",
            'learning_resources': f"https://github.com/topics/{topic.replace(' ', '-')}"
        }
    }

    if course in github_resources:
        for resource_type, url in github_resources[course].items():
            resources.append({
                'title': f"GitHub {resource_type.replace('_', ' ').title()}",
                'url': url,
                'type': 'repository'
            })

    # Add interactive learning platforms
    interactive_platforms = {
        'computer_science': {
            'codecademy': 'https://www.codecademy.com/catalog',
            'freecodecamp': 'https://www.freecodecamp.org/learn',
            'w3schools': 'https://www.w3schools.com'
        },
        'mechanical': {
            'autodesk': 'https://www.autodesk.com/certification/learn',
            'solidworks': 'https://my.solidworks.com/training'
        },
        'electrical': {
            'national_instruments': 'https://learn.ni.com/',
            'analog': 'https://www.analog.com/en/education.html'
        }
    }

    if course in interactive_platforms:
        for platform, url in interactive_platforms[course].items():
            resources.append({
                'title': f"Learn on {platform.replace('_', ' ').title()}",
                'url': url,
                'type': 'interactive'
            })

    return resources

def extract_resources(text):
    """Extract resources from AI analysis and combine with curated resources."""
    try:
        # Get the course and topic from the text
        course_match = re.search(r'Analyze this (\w+) engineering interview answer', text)
        topic_match = re.search(r'Question:.*?(\w+(?:\s+\w+)*?)\?', text)
        
        course = course_match.group(1) if course_match else 'computer_science'
        topic = topic_match.group(1).lower() if topic_match else 'general'
        
        # Get difficulty level
        difficulty = 'medium'  # default
        if 'advanced concepts' in text.lower():
            difficulty = 'advanced'
        elif 'basic concepts' in text.lower():
            difficulty = 'beginner'
            
        # Get curated resources
        resources = get_learning_resources(course, topic, difficulty)
        
        # Try to extract any additional resources mentioned in the AI analysis
        resources_section = re.search(r"Learning Resources:(.*?)(?:\n\n|$)", text, re.DOTALL)
        if resources_section:
            resources_text = resources_section.group(1)
            urls = re.findall(r'(?:https?://[^\s<>"]+|www\.[^\s<>"]+)', resources_text)
            
            for url in urls:
                # Try to find a title before the URL
                title_match = re.search(r'([^.\n]+)(?=.*?' + re.escape(url) + ')', resources_text)
                title = title_match.group(1).strip() if title_match else "Additional Resource"
                
                # Determine resource type
                resource_type = 'article'
                if 'youtube.com' in url.lower():
                    resource_type = 'video'
                elif 'documentation' in url.lower() or 'docs' in url.lower():
                    resource_type = 'documentation'
                elif 'tutorial' in url.lower():
                    resource_type = 'tutorial'
                elif 'course' in url.lower():
                    resource_type = 'course'
                
                resources.append({
                    'title': title,
                    'url': url,
                    'type': resource_type
                })
        
        return resources
    except Exception as e:
        print(f"Error extracting resources: {str(e)}")
        return []

@app.route('/ask', methods=['GET'])
@token_required
def ask_question(current_user):
    course = request.args.get('course')
    difficulty = request.args.get('difficulty', 'medium')
    
    if not course or course not in course_topics:
        return jsonify({'error': 'Invalid course'}), 400
        
    if difficulty not in difficulty_levels:
        difficulty = 'medium'

    try:
        question = generate_question(course, difficulty)
        return jsonify({
            'question': question,
            'difficulty': difficulty,
            'difficulty_info': difficulty_levels[difficulty]
        })
    except Exception as e:
        print(f"Error in /ask: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add a route to check server status
@app.route('/status', methods=['GET'])
def status():
    return jsonify({'status': 'Server is running', 'user_count': len(users)}), 200

@app.route('/user/progress', methods=['GET'])
@token_required
def get_progress(current_user):
    """Get user progress with proper authentication."""
    try:
        email = current_user['email']
        if email not in user_progress:
            # Initialize progress for new users
            user_progress[email] = {
                'totalQuestions': 0,
                'totalScore': 0,
                'bestScore': 0,
                'history': [],
                'questionsByCourse': {}
            }
        
        progress = user_progress[email]
        
        # Calculate averages and stats
        total_questions = progress['totalQuestions']
        response = {
            'totalQuestions': total_questions,
            'averageScore': progress['totalScore'] / max(total_questions, 1),
            'bestScore': progress['bestScore'],
            'history': progress['history'],
            'courseStats': {}
        }
        
        # Add course-specific stats
        for course, stats in progress.get('questionsByCourse', {}).items():
            course_total = stats['totalQuestions']
            response['courseStats'][course] = {
                'totalQuestions': course_total,
                'averageScore': stats['totalScore'] / max(course_total, 1),
                'bestScore': stats['bestScore']
            }
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error in get_progress: {str(e)}")
        return jsonify({'error': str(e)}), 500

def extract_topic(question):
    """Extract the main topic from the question."""
    # Remove common question patterns
    cleaned = question.lower().replace("what are", "").replace("how does", "").replace("explain", "")
    # Extract key technical terms
    words = cleaned.split()
    # Return the most likely technical term or default to general
    return words[-1] if words else "general"

if __name__ == '__main__':
    app.run(host=HOST, port=PORT, debug=True)