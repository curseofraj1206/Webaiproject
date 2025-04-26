# Engineering Interview Practice API

A sophisticated API for generating and analyzing engineering interview questions across various disciplines. The system uses AI to generate relevant questions and provide detailed feedback on responses.

## Features

- User authentication with JWT
- Specialized questions for different engineering disciplines
- AI-powered response analysis
- Progress tracking and performance metrics
- Cross-origin resource sharing (CORS) enabled

## Supported Engineering Disciplines

- Computer Science
- Mechanical Engineering
- Electrical Engineering
- Civil Engineering
- Chemical Engineering
- Biotechnology
- Aerospace Engineering

## Setup Instructions

### Prerequisites

- Python 3.x
- Flask
- Cohere API key

### Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd [repository-name]
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
Create a `.env` file in the root directory with the following variables:
```
SECRET_KEY=your-secret-key-here
COHERE_API_KEY=your-cohere-api-key
```

4. Run the server:
```bash
python server.py
```

## API Documentation

### Authentication Endpoints

#### Register User
- **URL**: `/register`
- **Method**: `POST`
- **Request Body**:
```json
{
    "email": "user@example.com",
    "password": "password123"
}
```
- **Response**:
```json
{
    "message": "Registration successful"
}
```

#### Login
- **URL**: `/login`
- **Method**: `POST`
- **Request Body**:
```json
{
    "email": "user@example.com",
    "password": "password123"
}
```
- **Response**:
```json
{
    "token": "jwt-token-string"
}
```

### Question Generation and Analysis

#### Get Question
- **URL**: `/ask`
- **Method**: `GET`
- **Headers**: `Authorization: Bearer <token>`
- **Query Parameters**:
  - `course` (optional): Specific engineering discipline
- **Response**:
```json
{
    "question": "Generated question text",
    "type": "question type"
}
```

#### Analyze Answer
- **URL**: `/analyze`
- **Method**: `POST`
- **Headers**: `Authorization: Bearer <token>`
- **Request Body**:
```json
{
    "answer": "User's answer text",
    "question": "Original question text"
}
```
- **Response**:
```json
{
    "feedback": "Detailed feedback",
    "score": 85
}
```

### Progress Tracking

#### Get User Progress
- **URL**: `/user/progress`
- **Method**: `GET`
- **Headers**: `Authorization: Bearer <token>`
- **Response**:
```json
{
    "totalQuestions": 10,
    "totalScore": 850,
    "bestScore": 95,
    "history": [
        {
            "question": "Question text",
            "score": 85,
            "timestamp": "2024-03-21T10:30:00Z"
        }
    ]
}
```

## Topic Coverage

Each engineering discipline includes questions covering fundamental and advanced topics:

### Computer Science
- Data Structures
- Algorithms
- Object-Oriented Programming
- Database Management
- Network Protocols
- Operating Systems
- Software Architecture
- Machine Learning
- Cybersecurity
- Cloud Computing
- Distributed Systems
- Web Development

### Mechanical Engineering
- Thermodynamics
- Fluid Mechanics
- Heat Transfer
- Machine Design
- Manufacturing Processes
- Robotics
- Materials Science
- Dynamics
- Control Systems
- Mechanical Vibrations
- CAD/CAM
- Mechatronics

### Electrical Engineering
- Circuit Analysis
- Digital Electronics
- Power Systems
- Electromagnetic Theory
- Signal Processing
- Control Systems
- Microelectronics
- Communication Systems
- Power Electronics
- Embedded Systems
- VLSI Design
- Renewable Energy

### Civil Engineering
- Structural Analysis
- Geotechnical Engineering
- Transportation
- Construction Management
- Environmental Engineering
- Hydraulics
- Surveying
- Concrete Technology
- Steel Structures
- Foundation Engineering
- Earthquake Engineering
- Urban Planning

### Chemical Engineering
- Mass Transfer
- Heat Transfer
- Fluid Dynamics
- Reaction Kinetics
- Process Control
- Thermodynamics
- Separation Processes
- Plant Design
- Process Safety
- Biochemical Engineering
- Polymer Science
- Catalysis

### Biotechnology
- Molecular Biology
- Genetic Engineering
- Fermentation
- Bioprocess Engineering
- Cell Culture
- Enzyme Technology
- Bioinformatics
- Immunology
- Tissue Engineering
- Protein Engineering
- Genomics
- Bioreactor Design

### Aerospace Engineering
- Aerodynamics
- Propulsion Systems
- Aircraft Structures
- Flight Mechanics
- Avionics
- Spacecraft Design
- Orbital Mechanics
- Composite Materials
- Flight Control
- Gas Dynamics
- Aircraft Stability
- Rocket Propulsion

## Error Handling

The API returns appropriate HTTP status codes and error messages:

- 200: Successful operation
- 201: Resource created successfully
- 400: Bad request / Invalid input
- 401: Unauthorized / Invalid token
- 500: Internal server error

## Security Considerations

- Passwords are hashed using secure methods
- JWT tokens expire after 24 hours
- CORS is configured to allow cross-origin requests
- API keys and secrets should be properly secured in production

## Rate Limiting

Please note that the Cohere API used for question generation and analysis has rate limits. Ensure your implementation handles these limits appropriately in a production environment. 