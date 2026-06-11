# 🛡 Wi-Fi Security Analyzer

A Python-based Evil Twin & Rogue AP detector with K-Means ML clustering.

## Features
- Detects Evil Twin attacks (duplicate SSIDs)
- K-Means clustering to classify Safe vs Malicious networks
- Risk scoring system (0–100)
- MAC vendor OUI lookup (offline)
- Randomized/spoofed MAC detection
- Color-coded terminal output
- Export reports to TXT/JSON
- Auto-rescan watch mode

## How it works
1. Scans nearby Wi-Fi using Windows netsh command
2. Extracts features: signal, auth type, duplicate SSID, MAC randomization
3. K-Means model clusters networks into Safe/Malicious
4. Displays threat report with confidence score

## Tech Stack
- Python 3.11
- scikit-learn (K-Means Clustering)
- pandas, numpy
- subprocess, re, json

## Run
pip install scikit-learn pandas numpy
python dataset_generator.py
python train_model.py
python project.py

## Sample Output
- 16 networks scanned
- 3 flagged as MEDIUM risk
- K-Means prediction with confidence %
