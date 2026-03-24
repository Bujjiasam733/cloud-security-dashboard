SEVERITY_COLORS = {
    "HIGH":   "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW":    "\033[92m",
    "INFO":   "\033[96m",
    "PASS":   "\033[92m",
}

RESET = "\033[0m"
BOLD  = "\033[1m"
CYAN  = "\033[96m"

def colorize(text, color):
    return f"{color}{text}{RESET}"

def severity_color(severity):
    return SEVERITY_COLORS.get(severity, RESET)