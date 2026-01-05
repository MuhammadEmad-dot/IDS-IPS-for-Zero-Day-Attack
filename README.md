# 🤖 AI-Powered Intrusion Detection & Prevention System for Zero-Day Attacks

## 🎯 Project Overview
A real-time AI-based security system that detects and blocks Zero-Day attacks using **One-Class Support Vector Machine (SVM)**. Unlike traditional systems that rely on known attack signatures, this system learns normal network behavior and identifies anomalies indicative of unknown threats.

**Group Members:**
- Muhammad Emad Uddin (IU04-0324-0080)
- Muhammad Hassan (IU04-0121-0046) 
- Muhammad Haris (IU04-0123-1047)

## 📊 Key Results
- **Packets Processed:** 290,000 network packets
- **AI Training:** 24,419 optimization iterations
- **Zero-Day Detection:** 95-98/100 threat scores
- **Automated Response:** IP blocking for threats >90/100
- **Processing Speed:** Real-time monitoring with <10ms response

## 🚀 Quick Start

### 1. Prerequisites
- **Python 3.11.9** (Required for library compatibility)
- **Git** (Optional, for version control)

### 2. Setup Instructions
```bash
# Clone the repository
git clone https://github.com/[your-username]/AI-IDS-Project.git
cd AI-IDS-Project

# Create virtual environment (Windows)
py -3.11 -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\activate.ps1
# Windows CMD:
.venv\Scripts\activate.bat

# Install dependencies
pip install -r requirements.txt