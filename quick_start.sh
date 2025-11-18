#!/bin/bash
# Quick Start Script for Advanced Phishing Training Generator
# ⚠️ FOR CYBERSECURITY TRAINING ONLY ⚠️

echo "======================================================================"
echo "⚠️  Advanced Phishing Training Generator - Quick Start"
echo "======================================================================"
echo ""

# Check if Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo "❌ Ollama not found!"
    echo "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    echo "✅ Ollama installed"
else
    echo "✅ Ollama already installed"
fi

# Check if Ollama is running
if ! curl -s http://localhost:11434/api/version &> /dev/null; then
    echo "Starting Ollama..."
    ollama serve &
    sleep 3
    echo "✅ Ollama started"
else
    echo "✅ Ollama is running"
fi

# Pull the model
echo ""
echo "Checking phishing email generator model..."
if ollama list | grep -q "phishing_email_generator"; then
    echo "✅ Model already downloaded"
else
    echo "Downloading model (this may take a few minutes)..."
    ollama pull JoannaF/phishing_email_generator
    echo "✅ Model downloaded"
fi

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install -q ollama requests fastapi uvicorn pydantic python-dotenv
echo "✅ Dependencies installed"

# Create .env if not exists
if [ ! -f .env ]; then
    echo ""
    echo "Creating .env file..."
    cp .env.example .env
    echo "✅ .env created (edit it to add your VirusTotal API key)"
fi

# Check if companies file exists
if [ ! -f companies_500.txt ]; then
    echo ""
    echo "⚠️  companies_500.txt not found!"
    echo "You'll need to add company names manually or download the file."
fi

echo ""
echo "======================================================================"
echo "✅ Setup Complete! Choose how to run:"
echo "======================================================================"
echo ""
echo "Option 1: Web Interface (Recommended)"
echo "  Command: python api_advanced.py"
echo "  Then open: http://localhost:8000"
echo ""
echo "Option 2: Command Line"
echo "  Command: python generate_phishing_advanced.py"
echo ""
echo "Option 3: Original Fast Version"
echo "  Command: python generate_phishing.py"
echo ""
echo "⚠️  REMEMBER: FOR TRAINING PURPOSES ONLY!"
echo "======================================================================"
