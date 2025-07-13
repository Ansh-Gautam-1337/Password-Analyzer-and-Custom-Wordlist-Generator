# 🔐 Password Strength Analyzer & Custom Wordlist Generator

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)

## 📌 Overview

The **Password Strength Analyzer & Custom Wordlist Generator** is a powerful GUI-based tool built using **Python** and **Tkinter**. It provides two core functionalities:

- 🔍 **Password Strength Analysis** using entropy, character diversity, and pattern recognition
- 🧾 **Custom Wordlist Generation** based on user-provided metadata (names, dates, nicknames, etc.)

Useful for cybersecurity students, ethical hackers, or users looking to test and harden password security.

---

## 🚀 Features

### ✅ Password Strength Analyzer

- Real-time entropy & score calculation
- Detection of:
  - Common passwords
  - Keyboard patterns
  - Repeated/sequential characters
  - Dates and leetspeak
- Feedback & improvement suggestions
- Time-to-crack estimation
- GUI visual indicators (score bar, metrics)
- CLI support for batch analysis

### ✅ Wordlist Generator

- Accepts:
  - Names, surnames, nicknames
  - Company, pet names
  - Birthdates
  - Custom keywords
- Applies:
  - Capitalization, reversal, doubling
  - Leetspeak transformations
  - Append numbers, years, and symbols
- Combines words intelligently
- GUI + CLI generation options
- Export wordlists as `.txt` or `.json`

---

## 🖥 GUI Interface

### Tabs:

1. **Password Analysis**
   - Input password
   - View strength, entropy, feedback
   - Visual metrics and progress bars
2. **Wordlist Generator**
   - Enter personal data & custom keywords
   - Control transformations (leetspeak, years, symbols)
   - View and save generated wordlist
3. **Results & Export**
   - History of analyses & wordlists
   - Export to TXT/JSON
   - Clear session history

---

## ⚙️ Installation

### 🔗 Prerequisites

- Python 3.9 or higher
- Recommended: Virtual environment

### 📦 Install Dependencies

```bash
pip install -r requirements.txt
```

> Note: If `requirements.txt` is not provided, ensure the following packages are available:
```bash
pip install tkinter
```

---

## 🚀 Usage

### 🖱 GUI Mode

```bash
python Password\ Analyzer\ and\ Custom\ Worlist.py --gui
```

### 🔧 CLI Mode

**Analyze a Password:**
```bash
python Password\ Analyzer\ and\ Custom\ Worlist.py -p "YourPassword123!"
```

**Generate a Wordlist:**
```bash
python Password\ Analyzer\ and\ Custom\ Worlist.py -w "john,doe,fluffy" -o mywordlist.txt
```

---

## 📂 Project Structure

```
📦 PasswordAnalyzer
├── Password Analyzer and Custom Worlist.py  # Main script (GUI + CLI)
├── README.md                                # Documentation
└── icon.ico                                 # Optional GUI icon
```

---

## 📤 Output & Export Options

- **Password Analysis**:
  - Entropy score
  - Strength label
  - Time to crack
  - Export to `.txt`

- **Wordlist**:
  - Export as `.txt` or `.json`
  - Statistics: word count, avg. length, unique lengths

---

## 🛡 Security & Ethics

This tool is intended for:

- Personal security auditing
- Cybersecurity education
- Ethical penetration testing

**❗ Not intended for illegal purposes. Always get proper authorization before using wordlists or testing security.**

---

## 🧠 Future Enhancements

- 🔄 Password breach API integration (e.g., HaveIBeenPwned)
- 🌐 Web-based version (Flask or Django)
- 📊 Chart-based feedback (Matplotlib, Plotly)
- 📱 Mobile-responsive redesign

---

## 👨‍💻 Author

**Ansh Gautam**  
Cybersecurity Enthusiast and Developer  

---

## 📄 License

This project is licensed under the **MIT License**.
