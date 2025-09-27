#!/bin/bash

echo "Extension Security Scanner - Quick Start"
echo "========================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

echo "[1/5] Creating virtual environment..."
python3 -m venv venv

echo "[2/5] Activating virtual environment..."
source venv/bin/activate

echo "[3/5] Installing dependencies..."
pip install -r requirements.txt

echo "[4/5] Running initial scan..."
python src/main.py --format markdown --output initial_scan.md

echo "[5/5] Scan complete!"
echo ""
echo "Results saved to: initial_scan.md"
echo ""
echo "To run future scans:"
echo "  source venv/bin/activate"
echo "  python src/main.py [options]"
echo ""
echo "For help:"
echo "  python src/main.py --help"