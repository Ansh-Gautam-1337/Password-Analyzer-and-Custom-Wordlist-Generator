import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import re
import math
import string
import itertools
import argparse
import sys
import os
from datetime import datetime
from typing import List, Dict, Set, Tuple
import json

class PasswordAnalyzer:
    """Core password analysis functionality"""
    
    def __init__(self):
        self.common_passwords = self._load_common_passwords()
        self.keyboard_patterns = self._get_keyboard_patterns()
        
    def _load_common_passwords(self) -> Set[str]:
        """Load common passwords for checking"""
        common = {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "1234567890", "abc123",
            "password1", "123456789", "welcome123", "admin123",
            "root", "toor", "pass", "test", "guest", "user",
            "login", "passw0rd", "p@ssw0rd", "123qwe", "qwe123"
        }
        return common
    
    def _get_keyboard_patterns(self) -> List[str]:
        """Get common keyboard patterns"""
        return [
            "qwerty", "asdf", "zxcv", "qwertyuiop", "asdfghjkl",
            "zxcvbnm", "1234567890", "!@#$%^&*()", "qaz", "wsx",
            "edc", "rfv", "tgb", "yhn", "ujm", "ik", "ol", "p"
        ]
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy"""
        if not password:
            return 0.0
        
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?/`~]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0.0
        
        return len(password) * math.log2(charset_size)
    
    def analyze_password(self, password: str) -> Dict:
        """Comprehensive password analysis"""
        if not password:
            return {"error": "Empty password"}
        
        analysis = {
            "password": password,
            "length": len(password),
            "entropy": self.calculate_entropy(password),
            "score": 0,
            "strength": "Very Weak",
            "feedback": [],
            "character_analysis": self._analyze_characters(password),
            "patterns": self._detect_patterns(password),
            "common_password": password.lower() in self.common_passwords,
            "time_to_crack": self._estimate_crack_time(password)
        }
        
        # Calculate score and strength
        score = self._calculate_score(password, analysis)
        analysis["score"] = score
        analysis["strength"] = self._get_strength_label(score)
        analysis["feedback"] = self._generate_feedback(password, analysis)
        
        return analysis
    
    def _analyze_characters(self, password: str) -> Dict:
        """Analyze character composition"""
        return {
            "lowercase": len(re.findall(r'[a-z]', password)),
            "uppercase": len(re.findall(r'[A-Z]', password)),
            "digits": len(re.findall(r'[0-9]', password)),
            "special": len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?/`~]', password)),
            "has_lowercase": bool(re.search(r'[a-z]', password)),
            "has_uppercase": bool(re.search(r'[A-Z]', password)),
            "has_digits": bool(re.search(r'[0-9]', password)),
            "has_special": bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?/`~]', password))
        }
    
    def _detect_patterns(self, password: str) -> Dict:
        """Detect common patterns in password"""
        patterns = {
            "keyboard_pattern": False,
            "repeated_chars": False,
            "sequential": False,
            "dictionary_word": False,
            "date_pattern": False,
            "leetspeak": False
        }
        
        # Check for keyboard patterns
        password_lower = password.lower()
        for pattern in self.keyboard_patterns:
            if pattern in password_lower:
                patterns["keyboard_pattern"] = True
                break
        
        # Check for repeated characters
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                patterns["repeated_chars"] = True
                break
        
        # Check for sequential characters
        for i in range(len(password) - 2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and 
                ord(password[i+2]) == ord(password[i]) + 2):
                patterns["sequential"] = True
                break
        
        # Check for date patterns
        if re.search(r'\d{4}|\d{2}/\d{2}|\d{2}-\d{2}', password):
            patterns["date_pattern"] = True
        
        # Check for leetspeak
        leetspeak_chars = {'@': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't'}
        if any(char in password for char in leetspeak_chars.keys()):
            patterns["leetspeak"] = True
        
        return patterns
    
    def _calculate_score(self, password: str, analysis: Dict) -> int:
        """Calculate password strength score (0-100)"""
        score = 0
        
        # Length scoring
        length = len(password)
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 20
        elif length >= 6:
            score += 10
        elif length >= 4:
            score += 5
        
        # Character diversity
        char_analysis = analysis["character_analysis"]
        diversity_score = 0
        if char_analysis["has_lowercase"]:
            diversity_score += 5
        if char_analysis["has_uppercase"]:
            diversity_score += 5
        if char_analysis["has_digits"]:
            diversity_score += 5
        if char_analysis["has_special"]:
            diversity_score += 10
        
        score += diversity_score
        
        # Entropy bonus
        entropy = analysis["entropy"]
        if entropy >= 60:
            score += 25
        elif entropy >= 40:
            score += 20
        elif entropy >= 25:
            score += 15
        elif entropy >= 15:
            score += 10
        
        # Penalties
        patterns = analysis["patterns"]
        if patterns["keyboard_pattern"]:
            score -= 10
        if patterns["repeated_chars"]:
            score -= 10
        if patterns["sequential"]:
            score -= 10
        if patterns["date_pattern"]:
            score -= 5
        if analysis["common_password"]:
            score -= 25
        
        # Ensure score is within bounds
        return max(0, min(100, score))
    
    def _get_strength_label(self, score: int) -> str:
        """Convert score to strength label"""
        if score >= 80:
            return "Very Strong"
        elif score >= 60:
            return "Strong"
        elif score >= 40:
            return "Moderate"
        elif score >= 20:
            return "Weak"
        else:
            return "Very Weak"
    
    def _generate_feedback(self, password: str, analysis: Dict) -> List[str]:
        """Generate feedback for password improvement"""
        feedback = []
        
        if len(password) < 8:
            feedback.append("Use at least 8 characters")
        elif len(password) < 12:
            feedback.append("Consider using 12 or more characters for better security")
        
        char_analysis = analysis["character_analysis"]
        if not char_analysis["has_lowercase"]:
            feedback.append("Add lowercase letters")
        if not char_analysis["has_uppercase"]:
            feedback.append("Add uppercase letters")
        if not char_analysis["has_digits"]:
            feedback.append("Add numbers")
        if not char_analysis["has_special"]:
            feedback.append("Add special characters (!@#$%^&*)")
        
        patterns = analysis["patterns"]
        if patterns["keyboard_pattern"]:
            feedback.append("Avoid keyboard patterns like 'qwerty'")
        if patterns["repeated_chars"]:
            feedback.append("Avoid repeated characters")
        if patterns["sequential"]:
            feedback.append("Avoid sequential characters")
        if patterns["date_pattern"]:
            feedback.append("Avoid using dates")
        if analysis["common_password"]:
            feedback.append("This is a commonly used password - choose something unique")
        
        if not feedback:
            feedback.append("Excellent password strength!")
        
        return feedback
    
    def _estimate_crack_time(self, password: str) -> str:
        """Estimate time to crack password"""
        entropy = self.calculate_entropy(password)
        if entropy <= 0:
            return "Instantly"
        
        attempts_per_second = 1e9  # 1 billion attempts per second
        combinations = 2 ** entropy
        seconds = combinations / (2 * attempts_per_second)  # Average case
        
        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 31536000000:
            return f"{seconds/31536000:.1f} years"
        else:
            return "Centuries"


class WordlistGenerator:
    """Custom wordlist generation functionality"""
    
    def __init__(self):
        self.years = [str(year) for year in range(1950, 2030)]
        self.months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun',
                      'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
        self.common_numbers = ['0', '1', '2', '3', '12', '123', '1234', '12345']
        self.common_symbols = ['!', '@', '#', '$', '123', '321']
        
    def generate_base_words(self, user_info: Dict) -> Set[str]:
        """Generate base words from user information"""
        base_words = set()
        
        # Add provided information
        if user_info.get('name'):
            base_words.add(user_info['name'].lower())
        if user_info.get('surname'):
            base_words.add(user_info['surname'].lower())
        if user_info.get('nickname'):
            base_words.add(user_info['nickname'].lower())
        if user_info.get('pet_name'):
            base_words.add(user_info['pet_name'].lower())
        if user_info.get('company'):
            base_words.add(user_info['company'].lower())
        if user_info.get('birthdate'):
            base_words.add(user_info['birthdate'])
        
        # Add custom words
        if user_info.get('custom_words'):
            for word in user_info['custom_words']:
                if word.strip():
                    base_words.add(word.strip().lower())
        
        return base_words
    
    def apply_transformations(self, base_words: Set[str]) -> List[str]:
        """Apply various transformations to base words"""
        wordlist = []
        
        for word in base_words:
            if not word:
                continue
                
            # Original word
            wordlist.append(word)
            wordlist.append(word.capitalize())
            wordlist.append(word.upper())
            
            # Leetspeak transformations
            leetspeak_word = self.to_leetspeak(word)
            if leetspeak_word != word:
                wordlist.append(leetspeak_word)
                wordlist.append(leetspeak_word.capitalize())
            
            # Reverse
            wordlist.append(word[::-1])
            
            # With numbers
            for num in self.common_numbers:
                wordlist.append(word + num)
                wordlist.append(num + word)
                wordlist.append(word.capitalize() + num)
            
            # With years
            for year in self.years[-20:]:  # Last 20 years
                wordlist.append(word + year)
                wordlist.append(year + word)
                wordlist.append(word.capitalize() + year)
            
            # With symbols
            for symbol in self.common_symbols:
                wordlist.append(word + symbol)
                wordlist.append(symbol + word)
            
            # Common patterns
            wordlist.append(word + "123")
            wordlist.append(word + "!")
            wordlist.append(word + "@")
            wordlist.append("123" + word)
            
            # Doubled words
            wordlist.append(word + word)
            wordlist.append(word + word.capitalize())
        
        # Combinations of words
        base_words_list = list(base_words)
        if len(base_words_list) > 1:
            for i in range(len(base_words_list)):
                for j in range(i+1, len(base_words_list)):
                    word1, word2 = base_words_list[i], base_words_list[j]
                    wordlist.append(word1 + word2)
                    wordlist.append(word2 + word1)
                    wordlist.append(word1.capitalize() + word2)
                    wordlist.append(word1 + word2.capitalize())
        
        return list(set(wordlist))  # Remove duplicates
    
    def to_leetspeak(self, word: str) -> str:
        """Convert word to leetspeak"""
        leetspeak_map = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7',
            'l': '1', 'g': '9', 'b': '6'
        }
        
        result = ""
        for char in word.lower():
            result += leetspeak_map.get(char, char)
        
        return result
    
    def generate_wordlist(self, user_info: Dict) -> List[str]:
        """Generate complete wordlist"""
        base_words = self.generate_base_words(user_info)
        if not base_words:
            return []
        
        wordlist = self.apply_transformations(base_words)
        
        # Sort by length and alphabetically
        wordlist.sort(key=lambda x: (len(x), x))
        
        return wordlist


class PasswordToolGUI:
    """Main GUI application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer & Wordlist Generator")
        self.root.geometry("1000x800")
        self.root.configure(bg='#f0f0f0')
        
        # Initialize components
        self.analyzer = PasswordAnalyzer()
        self.wordlist_generator = WordlistGenerator()
        
        # Create main interface
        self.create_widgets()
        
        # Bind events
        self.root.bind('<Control-n>', lambda e: self.new_analysis())
        self.root.bind('<Control-s>', lambda e: self.save_results())
        self.root.bind('<Control-o>', lambda e: self.load_wordlist())
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_password_analysis_tab()
        self.create_wordlist_generation_tab()
        self.create_results_tab()
        
        # Status bar
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_password_analysis_tab(self):
        """Create password analysis tab"""
        # Password Analysis Tab
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="Password Analysis")
        
        # Main container
        main_container = ttk.Frame(analysis_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Input section
        input_frame = ttk.LabelFrame(main_container, text="Password Input", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(input_frame, text="Enter Password:").pack(anchor=tk.W)
        self.password_entry = tk.Entry(input_frame, show="*", font=("Consolas", 12), width=50)
        self.password_entry.pack(fill=tk.X, pady=(5, 10))
        self.password_entry.bind('<KeyRelease>', self.on_password_change)
        
        # Show/Hide password
        self.show_password_var = tk.BooleanVar()
        show_password_cb = tk.Checkbutton(input_frame, text="Show Password", 
                                     variable=self.show_password_var,
                                     command=self.toggle_password_visibility)
        show_password_cb.pack(anchor=tk.W)
        
        # Analysis button
        analyze_btn = tk.Button(input_frame, text="Analyze Password", 
                              command=self.analyze_password, bg="#4CAF50", fg="white",
                              font=("Arial", 10, "bold"))
        analyze_btn.pack(pady=(10, 0))
        
        # Results section
        results_frame = ttk.LabelFrame(main_container, text="Analysis Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create two columns
        left_column = ttk.Frame(results_frame)
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        right_column = ttk.Frame(results_frame)
        right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Strength indicator
        strength_frame = ttk.LabelFrame(left_column, text="Strength Assessment", padding="10")
        strength_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.strength_label = tk.Label(strength_frame, text="No analysis yet", 
                                     font=("Arial", 14, "bold"))
        self.strength_label.pack()
        
        self.score_label = tk.Label(strength_frame, text="Score: -/100")
        self.score_label.pack()
        
        # Progress bar for strength
        self.strength_progress = ttk.Progressbar(strength_frame, length=300, mode='determinate')
        self.strength_progress.pack(pady=(10, 0))
        
        # Metrics
        metrics_frame = ttk.LabelFrame(left_column, text="Metrics", padding="10")
        metrics_frame.pack(fill=tk.BOTH, expand=True)
        
        self.metrics_text = scrolledtext.ScrolledText(metrics_frame, height=10, width=40)
        self.metrics_text.pack(fill=tk.BOTH, expand=True)
        
        # Feedback
        feedback_frame = ttk.LabelFrame(right_column, text="Recommendations", padding="10")
        feedback_frame.pack(fill=tk.BOTH, expand=True)
        
        self.feedback_text = scrolledtext.ScrolledText(feedback_frame, height=15, width=40)
        self.feedback_text.pack(fill=tk.BOTH, expand=True)
    
    def create_wordlist_generation_tab(self):
        """Create wordlist generation tab"""
        # Wordlist Generation Tab
        wordlist_frame = ttk.Frame(self.notebook)
        self.notebook.add(wordlist_frame, text="Wordlist Generation")
        
        # Main container
        main_container = ttk.Frame(wordlist_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Input section
        input_frame = ttk.LabelFrame(main_container, text="Target Information", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create input grid
        input_grid = ttk.Frame(input_frame)
        input_grid.pack(fill=tk.X)
        
        # Left column inputs
        left_inputs = ttk.Frame(input_grid)
        left_inputs.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        tk.Label(left_inputs, text="First Name:").pack(anchor=tk.W)
        self.name_entry = tk.Entry(left_inputs, width=30)
        self.name_entry.pack(fill=tk.X, pady=(2, 10))
        
        tk.Label(left_inputs, text="Last Name:").pack(anchor=tk.W)
        self.surname_entry = tk.Entry(left_inputs, width=30)
        self.surname_entry.pack(fill=tk.X, pady=(2, 10))
        
        tk.Label(left_inputs, text="Nickname:").pack(anchor=tk.W)
        self.nickname_entry = tk.Entry(left_inputs, width=30)
        self.nickname_entry.pack(fill=tk.X, pady=(2, 10))
        
        # Right column inputs
        right_inputs = ttk.Frame(input_grid)
        right_inputs.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        tk.Label(right_inputs, text="Pet Name:").pack(anchor=tk.W)
        self.pet_entry = tk.Entry(right_inputs, width=30)
        self.pet_entry.pack(fill=tk.X, pady=(2, 10))
        
        tk.Label(right_inputs, text="Company:").pack(anchor=tk.W)
        self.company_entry = tk.Entry(right_inputs, width=30)
        self.company_entry.pack(fill=tk.X, pady=(2, 10))
        
        tk.Label(right_inputs, text="Birth Date (DDMMYYYY):").pack(anchor=tk.W)
        self.birthdate_entry = tk.Entry(right_inputs, width=30)
        self.birthdate_entry.pack(fill=tk.X, pady=(2, 10))
        
        # Custom words section
        custom_frame = ttk.LabelFrame(main_container, text="Additional Words", padding="10")
        custom_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(custom_frame, text="Custom Words (one per line):").pack(anchor=tk.W)
        self.custom_words_text = scrolledtext.ScrolledText(custom_frame, height=5, width=70)
        self.custom_words_text.pack(fill=tk.X, pady=(5, 0))
        
        # Generation options
        options_frame = ttk.LabelFrame(main_container, text="Generation Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        options_grid = ttk.Frame(options_frame)
        options_grid.pack(fill=tk.X)
        
        self.leetspeak_var = tk.BooleanVar(value=True)
        self.years_var = tk.BooleanVar(value=True)
        self.numbers_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.combinations_var = tk.BooleanVar(value=True)
        
        tk.Checkbutton(options_grid, text="Include Leetspeak", variable=self.leetspeak_var).pack(side=tk.LEFT)
        tk.Checkbutton(options_grid, text="Append Years", variable=self.years_var).pack(side=tk.LEFT)
        tk.Checkbutton(options_grid, text="Append Numbers", variable=self.numbers_var).pack(side=tk.LEFT)
        tk.Checkbutton(options_grid, text="Append Symbols", variable=self.symbols_var).pack(side=tk.LEFT)
        tk.Checkbutton(options_grid, text="Word Combinations", variable=self.combinations_var).pack(side=tk.LEFT)
        
        # Generation controls
        controls_frame = ttk.Frame(main_container)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        generate_btn = tk.Button(controls_frame, text="Generate Wordlist", 
                               command=self.generate_wordlist, bg="#2196F3", fg="white",
                               font=("Arial", 10, "bold"))
        generate_btn.pack(side=tk.LEFT)
        
        clear_btn = tk.Button(controls_frame, text="Clear All", 
                            command=self.clear_wordlist_inputs, bg="#FF9800", fg="white")
        clear_btn.pack(side=tk.LEFT, padx=(10, 0))
        
        save_btn = tk.Button(controls_frame, text="Save Wordlist", 
                           command=self.save_wordlist, bg="#4CAF50", fg="white")
        save_btn.pack(side=tk.RIGHT)
        
        # Results section
        results_frame = ttk.LabelFrame(main_container, text="Generated Wordlist", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Wordlist display with scrollbar
        wordlist_container = ttk.Frame(results_frame)
        wordlist_container.pack(fill=tk.BOTH, expand=True)
        
        self.wordlist_text = scrolledtext.ScrolledText(wordlist_container, height=15, width=80,
                                                     font=("Consolas", 9))
        self.wordlist_text.pack(fill=tk.BOTH, expand=True)
        
        # Statistics
        self.wordlist_stats_label = tk.Label(results_frame, text="No wordlist generated yet")
        self.wordlist_stats_label.pack(pady=(10, 0))
    
    def create_results_tab(self):
        """Create results and export tab"""
        # Results Tab
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results & Export")
        
        # Main container
        main_container = ttk.Frame(results_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Export options
        export_frame = ttk.LabelFrame(main_container, text="Export Options", padding="10")
        export_frame.pack(fill=tk.X, pady=(0, 10))
        
        export_grid = ttk.Frame(export_frame)
        export_grid.pack(fill=tk.X)
        
        # Export buttons
        export_analysis_btn = tk.Button(export_grid, text="Export Analysis Report", 
                                      command=self.export_analysis_report, bg="#673AB7", fg="white")
        export_analysis_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        export_wordlist_btn = tk.Button(export_grid, text="Export Wordlist (TXT)", 
                                      command=self.export_wordlist_txt, bg="#009688", fg="white")
        export_wordlist_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        export_json_btn = tk.Button(export_grid, text="Export All (JSON)", 
                                  command=self.export_all_json, bg="#795548", fg="white")
        export_json_btn.pack(side=tk.LEFT)
        
        # Results history
        history_frame = ttk.LabelFrame(main_container, text="Session History", padding="10")
        history_frame.pack(fill=tk.BOTH, expand=True)
        
        self.history_text = scrolledtext.ScrolledText(history_frame, height=20, width=80,
                                                    font=("Consolas", 9))
        self.history_text.pack(fill=tk.BOTH, expand=True)
        
        # Clear history button
        clear_history_btn = tk.Button(history_frame, text="Clear History", 
                                    command=self.clear_history, bg="#F44336", fg="white")
        clear_history_btn.pack(pady=(10, 0))
        
        # Initialize results storage
        self.analysis_results = []
        self.generated_wordlists = []
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")
    
    def on_password_change(self, event=None):
        """Handle password change event"""
        # Auto-analyze if enabled
        password = self.password_entry.get()
        if len(password) > 0:
            self.update_status(f"Password length: {len(password)} characters")
    
    def analyze_password(self):
        """Analyze the entered password"""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password to analyze")
            return
        
        try:
            # Perform analysis
            analysis = self.analyzer.analyze_password(password)
            
            # Update UI with results
            self.display_analysis_results(analysis)
            
            # Store result for history
            self.analysis_results.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'analysis': analysis
            })
            
            # Update history
            self.update_analysis_history(analysis)
            
            self.update_status("Password analysis completed")
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
            self.update_status("Analysis failed")
    
    def display_analysis_results(self, analysis):
        """Display analysis results in the GUI"""
        # Update strength indicator
        strength = analysis['strength']
        score = analysis['score']
        
        self.strength_label.configure(text=strength)
        self.score_label.configure(text=f"Score: {score}/100")
        
        # Update progress bar
        self.strength_progress['value'] = score
        
        # Set color based on strength
        colors = {
            'Very Weak': '#F44336',
            'Weak': '#FF9800',
            'Moderate': '#FFC107',
            'Strong': '#8BC34A',
            'Very Strong': '#4CAF50'
        }
        color = colors.get(strength, '#9E9E9E')
        self.strength_label.configure(fg=color)
        
        # Update metrics
        self.metrics_text.delete(1.0, tk.END)
        metrics = f"""Password Length: {analysis['length']} characters
Entropy: {analysis['entropy']:.2f} bits
Time to Crack: {analysis['time_to_crack']}

Character Analysis:
- Lowercase: {analysis['character_analysis']['lowercase']}
- Uppercase: {analysis['character_analysis']['uppercase']}
- Digits: {analysis['character_analysis']['digits']}
- Special: {analysis['character_analysis']['special']}

Pattern Detection:
- Common Password: {'Yes' if analysis['common_password'] else 'No'}
- Keyboard Pattern: {'Yes' if analysis['patterns']['keyboard_pattern'] else 'No'}
- Repeated Characters: {'Yes' if analysis['patterns']['repeated_chars'] else 'No'}
- Sequential Characters: {'Yes' if analysis['patterns']['sequential'] else 'No'}
- Date Pattern: {'Yes' if analysis['patterns']['date_pattern'] else 'No'}
- Leetspeak: {'Yes' if analysis['patterns']['leetspeak'] else 'No'}"""
        
        self.metrics_text.insert(tk.END, metrics)
        
        # Update feedback
        self.feedback_text.delete(1.0, tk.END)
        feedback_text = "Recommendations:\n\n"
        for i, feedback in enumerate(analysis['feedback'], 1):
            feedback_text += f"{i}. {feedback}\n"
        
        if analysis['score'] >= 80:
            feedback_text += "\n✓ This password has excellent security!"
        elif analysis['score'] >= 60:
            feedback_text += "\n✓ This password has good security."
        else:
            feedback_text += "\n⚠ Consider improving this password."
        
        self.feedback_text.insert(tk.END, feedback_text)
    
    def generate_wordlist(self):
        """Generate custom wordlist"""
        try:
            # Collect user information
            user_info = {
                'name': self.name_entry.get().strip(),
                'surname': self.surname_entry.get().strip(),
                'nickname': self.nickname_entry.get().strip(),
                'pet_name': self.pet_entry.get().strip(),
                'company': self.company_entry.get().strip(),
                'birthdate': self.birthdate_entry.get().strip(),
                'custom_words': self.custom_words_text.get(1.0, tk.END).strip().split('\n')
            }
            
            # Check if any information is provided
            has_info = any(user_info[key] for key in user_info if key != 'custom_words')
            has_custom = any(word.strip() for word in user_info['custom_words'])
            
            if not has_info and not has_custom:
                messagebox.showwarning("Warning", "Please provide at least some target information")
                return
            
            # Generate wordlist
            wordlist = self.wordlist_generator.generate_wordlist(user_info)
            
            if not wordlist:
                messagebox.showinfo("Info", "No wordlist could be generated from the provided information")
                return
            
            # Display wordlist
            self.display_wordlist(wordlist, user_info)
            
            # Store for history
            self.generated_wordlists.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'user_info': user_info,
                'wordlist': wordlist,
                'count': len(wordlist)
            })
            
            # Update history
            self.update_wordlist_history(wordlist, user_info)
            
            self.update_status(f"Generated wordlist with {len(wordlist)} entries")
            
        except Exception as e:
            messagebox.showerror("Error", f"Wordlist generation failed: {str(e)}")
            self.update_status("Wordlist generation failed")
    
    def display_wordlist(self, wordlist, user_info):
        """Display generated wordlist"""
        # Clear previous results
        self.wordlist_text.delete(1.0, tk.END)
        
        # Add header with generation info
        header = f"# Generated Wordlist - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        header += f"# Target Information: {', '.join([f'{k}: {v}' for k, v in user_info.items() if v and k != 'custom_words'])}\n"
        header += f"# Total Entries: {len(wordlist)}\n"
        header += "#" + "="*50 + "\n\n"
        
        self.wordlist_text.insert(tk.END, header)
        
        # Add wordlist entries
        for word in wordlist:
            self.wordlist_text.insert(tk.END, word + "\n")
        
        # Update statistics
        unique_lengths = len(set(len(word) for word in wordlist))
        avg_length = sum(len(word) for word in wordlist) / len(wordlist)
        
        stats = f"Statistics: {len(wordlist)} entries, {unique_lengths} unique lengths, avg length: {avg_length:.1f}"
        self.wordlist_stats_label.configure(text=stats)
    
    def clear_wordlist_inputs(self):
        """Clear all wordlist input fields"""
        self.name_entry.delete(0, tk.END)
        self.surname_entry.delete(0, tk.END)
        self.nickname_entry.delete(0, tk.END)
        self.pet_entry.delete(0, tk.END)
        self.company_entry.delete(0, tk.END)
        self.birthdate_entry.delete(0, tk.END)
        self.custom_words_text.delete(1.0, tk.END)
        
        self.wordlist_text.delete(1.0, tk.END)
        self.wordlist_stats_label.configure(text="No wordlist generated yet")
        
        self.update_status("Wordlist inputs cleared")
    
    def save_wordlist(self):
        """Save generated wordlist to file"""
        wordlist_content = self.wordlist_text.get(1.0, tk.END).strip()
        if not wordlist_content:
            messagebox.showwarning("Warning", "No wordlist to save")
            return
        
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save Wordlist"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(wordlist_content)
                
                messagebox.showinfo("Success", f"Wordlist saved to {filename}")
                self.update_status(f"Wordlist saved to {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save wordlist: {str(e)}")
    
    def update_analysis_history(self, analysis):
        """Update analysis history"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        history_entry = f"\n[{timestamp}] Password Analysis\n"
        history_entry += f"Strength: {analysis['strength']} (Score: {analysis['score']}/100)\n"
        history_entry += f"Length: {analysis['length']}, Entropy: {analysis['entropy']:.2f} bits\n"
        history_entry += f"Time to crack: {analysis['time_to_crack']}\n"
        history_entry += "-" * 50 + "\n"
        
        self.history_text.insert(tk.END, history_entry)
        self.history_text.see(tk.END)
    
    def update_wordlist_history(self, wordlist, user_info):
        """Update wordlist generation history"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        history_entry = f"\n[{timestamp}] Wordlist Generation\n"
        history_entry += f"Target: {', '.join([f'{k}={v}' for k, v in user_info.items() if v and k != 'custom_words'])}\n"
        history_entry += f"Generated {len(wordlist)} entries\n"
        history_entry += f"Sample words: {', '.join(wordlist[:5])}{'...' if len(wordlist) > 5 else ''}\n"
        history_entry += "-" * 50 + "\n"
        
        self.history_text.insert(tk.END, history_entry)
        self.history_text.see(tk.END)
    
    def clear_history(self):
        """Clear session history"""
        self.history_text.delete(1.0, tk.END)
        self.analysis_results.clear()
        self.generated_wordlists.clear()
        self.update_status("History cleared")
    
    def export_analysis_report(self):
        """Export analysis report"""
        if not self.analysis_results:
            messagebox.showwarning("Warning", "No analysis results to export")
            return
        
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Export Analysis Report"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("PASSWORD STRENGTH ANALYSIS REPORT\n")
                    f.write("=" * 50 + "\n\n")
                    
                    for result in self.analysis_results:
                        analysis = result['analysis']
                        f.write(f"Analysis Date: {result['timestamp']}\n")
                        f.write(f"Password Length: {analysis['length']} characters\n")
                        f.write(f"Strength: {analysis['strength']} ({analysis['score']}/100)\n")
                        f.write(f"Entropy: {analysis['entropy']:.2f} bits\n")
                        f.write(f"Time to Crack: {analysis['time_to_crack']}\n\n")
                        
                        f.write("Character Analysis:\n")
                        char_analysis = analysis['character_analysis']
                        f.write(f"- Lowercase: {char_analysis['lowercase']}\n")
                        f.write(f"- Uppercase: {char_analysis['uppercase']}\n")
                        f.write(f"- Digits: {char_analysis['digits']}\n")
                        f.write(f"- Special: {char_analysis['special']}\n\n")
                        
                        f.write("Recommendations:\n")
                        for i, feedback in enumerate(analysis['feedback'], 1):
                            f.write(f"{i}. {feedback}\n")
                        
                        f.write("\n" + "-" * 50 + "\n\n")
                
                messagebox.showinfo("Success", f"Analysis report exported to {filename}")
                self.update_status(f"Analysis report exported to {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export analysis report: {str(e)}")
    
    def export_wordlist_txt(self):
        """Export wordlist as TXT file"""
        if not self.generated_wordlists:
            messagebox.showwarning("Warning", "No wordlists to export")
            return
        
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Export Wordlist"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("# CUSTOM WORDLIST FOR SECURITY TESTING\n")
                    f.write("# Generated by Password Strength Analyzer\n")
                    f.write(f"# Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("#" + "=" * 50 + "\n\n")
                    
                    # Export latest wordlist
                    latest_wordlist = self.generated_wordlists[-1]
                    for word in latest_wordlist['wordlist']:
                        f.write(word + "\n")
                
                messagebox.showinfo("Success", f"Wordlist exported to {filename}")
                self.update_status(f"Wordlist exported to {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export wordlist: {str(e)}")
    
    def export_all_json(self):
        """Export all results as JSON file"""
        if not self.analysis_results and not self.generated_wordlists:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Export All Results"
            )
            
            if filename:
                export_data = {
                    'export_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'analysis_results': self.analysis_results,
                    'generated_wordlists': self.generated_wordlists,
                    'summary': {
                        'total_analyses': len(self.analysis_results),
                        'total_wordlists': len(self.generated_wordlists),
                        'total_words_generated': sum(result['count'] for result in self.generated_wordlists)
                    }
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                
                messagebox.showinfo("Success", f"All results exported to {filename}")
                self.update_status(f"All results exported to {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {str(e)}")
    
    def new_analysis(self):
        """Start new analysis (clear current)"""
        self.password_entry.delete(0, tk.END)
        self.strength_label.configure(text="No analysis yet", fg="black")
        self.score_label.configure(text="Score: -/100")
        self.strength_progress['value'] = 0
        self.metrics_text.delete(1.0, tk.END)
        self.feedback_text.delete(1.0, tk.END)
        self.update_status("Ready for new analysis")
    
    def save_results(self):
        """Save current results"""
        if hasattr(self, 'current_analysis'):
            self.export_analysis_report()
        else:
            messagebox.showinfo("Info", "No current analysis to save")
    
    def load_wordlist(self):
        """Load wordlist from file"""
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Load Wordlist"
            )
            
            if filename:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.wordlist_text.delete(1.0, tk.END)
                self.wordlist_text.insert(tk.END, content)
                
                # Count lines (excluding comments)
                lines = [line for line in content.split('\n') if line.strip() and not line.startswith('#')]
                self.wordlist_stats_label.configure(text=f"Loaded {len(lines)} entries from file")
                
                self.update_status(f"Wordlist loaded from {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load wordlist: {str(e)}")
    
    def update_status(self, message):
        """Update status bar"""
        self.status_bar.configure(text=message)
        self.root.update_idletasks()


def create_cli_interface():
    """Create command-line interface"""
    parser = argparse.ArgumentParser(description="Password Strength Analyzer & Wordlist Generator")
    parser.add_argument("--password", "-p", help="Password to analyze")
    parser.add_argument("--wordlist", "-w", help="Generate wordlist with comma-separated info (name,surname,pet)")
    parser.add_argument("--output", "-o", help="Output file for wordlist")
    parser.add_argument("--gui", "-g", action="store_true", help="Launch GUI interface")
    
    return parser


def run_cli_mode(args):
    """Run in CLI mode"""
    analyzer = PasswordAnalyzer()
    wordlist_generator = WordlistGenerator()
    
    if args.password:
        print("Password Analysis Results:")
        print("=" * 40)
        
        analysis = analyzer.analyze_password(args.password)
        
        print(f"Password: {'*' * len(args.password)}")
        print(f"Length: {analysis['length']} characters")
        print(f"Strength: {analysis['strength']} ({analysis['score']}/100)")
        print(f"Entropy: {analysis['entropy']:.2f} bits")
        print(f"Time to Crack: {analysis['time_to_crack']}")
        print()
        
        print("Recommendations:")
        for i, feedback in enumerate(analysis['feedback'], 1):
            print(f"{i}. {feedback}")
    
    if args.wordlist:
        print("\nWordlist Generation:")
        print("=" * 40)
        
        info_parts = args.wordlist.split(',')
        user_info = {
            'name': info_parts[0] if len(info_parts) > 0 else '',
            'surname': info_parts[1] if len(info_parts) > 1 else '',
            'pet_name': info_parts[2] if len(info_parts) > 2 else '',
            'custom_words': info_parts[3:] if len(info_parts) > 3 else []
        }
        
        wordlist = wordlist_generator.generate_wordlist(user_info)
        
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(f"# Generated Wordlist - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Target: {args.wordlist}\n")
                    f.write(f"# Total Entries: {len(wordlist)}\n\n")
                    for word in wordlist:
                        f.write(word + "\n")
                
                print(f"Wordlist with {len(wordlist)} entries saved to {args.output}")
            except Exception as e:
                print(f"Error saving wordlist: {e}")
        else:
            print(f"Generated {len(wordlist)} entries:")
            for word in wordlist[:20]:  # Show first 20
                print(word)
            if len(wordlist) > 20:
                print(f"... and {len(wordlist) - 20} more entries")


def main():
    """Main application entry point"""
    parser = create_cli_interface()
    args = parser.parse_args()
    
    # Check if CLI arguments are provided
    if args.password or args.wordlist:
        run_cli_mode(args)
    else:
        # Launch GUI
        root = tk.Tk()
        app = PasswordToolGUI(root)
        
        # Set window icon (if available)
        try:
            root.iconbitmap('icon.ico')
        except:
            pass  # Icon file not found, use default
        
        # Center window on screen
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f'{width}x{height}+{x}+{y}')
        
        # Set minimum window size
        root.minsize(800, 600)
        
        # Start GUI event loop
        root.mainloop()


if __name__ == "__main__":
    main()