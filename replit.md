# Overview

This is an AI-powered research paper generation platform that enables users to create, manage, and format academic papers. The system provides a web-based interface for uploading research topics/abstracts, generating paper content through AI integration, and managing citations with multiple formatting styles. The platform features user authentication, paper management, and a modern responsive frontend with animated UI elements.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Technology Stack**: Vanilla HTML/CSS/JavaScript with modern CSS animations and transitions
- **Styling Framework**: Custom CSS with CSS variables for theming, Google Fonts (Inter, Playfair Display), and Font Awesome icons
- **Layout Pattern**: Responsive grid-based layouts with flexbox for component alignment
- **UI Components**: Modular template system using Flask's Jinja2 templating engine
- **Interactive Elements**: JavaScript-powered typewriter effects, counters, form validation, and smooth animations

## Backend Architecture
- **Framework**: Flask with SQLAlchemy ORM for database operations
- **Authentication**: JWT token-based authentication with decorator-based route protection
- **API Design**: RESTful API structure with JSON responses
- **Security**: Password hashing using Werkzeug security utilities, CORS enabled for cross-origin requests
- **Error Handling**: Centralized error responses with appropriate HTTP status codes

## Data Storage
- **Database**: SQLite for development with SQLAlchemy ORM abstraction
- **Schema Design**: 
  - Users table with email, name, password hash, and timestamps
  - Papers table with title, abstract, content, status, citation style, and user relationships
- **Relationships**: One-to-many relationship between users and papers with foreign key constraints

## Authentication & Authorization
- **Token Management**: JWT tokens with configurable secret key from environment variables
- **Session Handling**: Stateless authentication using Authorization headers
- **Access Control**: Decorator-based route protection requiring valid tokens for protected endpoints
- **Password Security**: Hashed passwords using Werkzeug's generate_password_hash

# External Dependencies

## Core Dependencies
- **Flask**: Web framework for Python backend
- **SQLAlchemy**: Database ORM and connection management
- **Flask-SQLAlchemy**: Flask integration for SQLAlchemy
- **Flask-CORS**: Cross-Origin Resource Sharing support
- **PyJWT**: JSON Web Token implementation for authentication
- **Werkzeug**: WSGI utilities including password hashing

## Frontend Libraries
- **Font Awesome 6.0.0**: Icon library from CDN
- **Google Fonts**: Inter and Playfair Display font families
- **CSS Grid/Flexbox**: Native CSS layout systems

## Environment Configuration
- **SESSION_SECRET**: Required environment variable for JWT token signing
- **SQLite Database**: File-based database storage (research_platform.db)

## Planned Integrations (Based on Requirements)
- **AI Services**: OpenAI API or custom language models for content generation
- **Academic APIs**: CrossRef and Semantic Scholar for research data
- **Citation Services**: Multiple citation style formatting (APA, IEEE, MLA, Chicago)
- **Document Export**: DOCX/PDF generation capabilities
- **Background Processing**: Celery with Redis for async task handling