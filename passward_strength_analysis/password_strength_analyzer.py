import re
import math
import os

# ---------------------------
# Password Strength Analyzer
# ---------------------------

def regex_checks(password):
    """Check password for character requirements."""
    return {
        "length": len(password) >= 8,
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password))
    }

def load_dictionary(wordlist="C:/Users/HP/Documents/projects/passward_strength_analysis/common_passwords.txt"):
    """Load a set of common passwords from file."""
    if not os.path.exists(wordlist):
        print(f"Warning: Password dictionary file '{wordlist}' not found.")
        return set()
    with open(wordlist, "r", encoding="utf-8") as f:
        return set(f.read().splitlines())

# Load common passwords once
common_passwords = load_dictionary()

def dictionary_check(password):
    """Check if password exists in the common passwords list."""
    return password.lower() in common_passwords

def calculate_entropy(password):
    """Calculate entropy and classify password strength."""
    if not password:
        return 0, "No password entered"

    if dictionary_check(password):
        return 0, "Very Weak (common password)"
    
    checks = regex_checks(password)
    pool_size = 0
    if checks["lower"]:
        pool_size += 26
    if checks["upper"]:
        pool_size += 26
    if checks["digit"]:
        pool_size += 10
    if checks["special"]:
        pool_size += 32

    if len(password) < 8:
        return 0, "Weak (too short)"
    
    # Calculate entropy in bits
    ent = round(len(password) * math.log2(pool_size), 2)
    
    # Classify strength
    if ent < 28:
        strength = "Weak"
    elif ent < 36:
        strength = "Moderate"
    elif ent < 60:
        strength = "Strong"
    else:
        strength = "Very Strong"
    
    return ent, strength

def suggest_improvements(password):
    """Suggest how to improve the password strength."""
    suggestions = []
    checks = regex_checks(password)

    if len(password) < 12:
        suggestions.append("Use at least 12 characters for better security.")
    if not checks["lower"]:
        suggestions.append("Add lowercase letters.")
    if not checks["upper"]:
        suggestions.append("Add uppercase letters.")
    if not checks["digit"]:
        suggestions.append("Include numbers.")
    if not checks["special"]:
        suggestions.append("Include special characters (e.g., @, #, $).")
    if dictionary_check(password):
        suggestions.append("Avoid common/dictionary passwords.")

    if not suggestions:
        return ["This password is strong. No major improvements needed! ✅"]

    return suggestions


def display_results(password):
    """Display password strength analysis."""
    checks = regex_checks(password)
    print(f"\nPassword: {password}")
    print("Character Checks:")
    for key, val in checks.items():
        status = "✅" if val else "❌"
        print(f"  {key.capitalize():6}: {status}")
    print(f"Dictionary Check: {'❌ Found in common passwords' if dictionary_check(password) else '✅ Not found'}")
    
    ent, strength = calculate_entropy(password)
    if ent > 0:
        print(f"Entropy: {ent} bits")
    print(f"Password Strength: {strength}")
    
    # Show suggestions
    print("Suggestions:")
    for s in suggest_improvements(password):
        print(f"  - {s}")
    print("-" * 40)



if __name__ == "__main__":
    print("=== Password Strength Analyzer ===")
    
    # Test passwords
    test_passwords = ["password", "Pass123", "Pass@123", "HELLO123!", "P@ssw0rd!9Zq"]
    for pwd in test_passwords:
        display_results(pwd)
    
    # Interactive mode
    while True:
        pwd = input("\nEnter a password to analyze (or 'exit' to quit): ")
        if pwd.lower() == "exit":
            break
        display_results(pwd)
