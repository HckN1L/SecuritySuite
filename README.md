Security Suite - Offensive & Defensive Web Tools

A web-based suite of security tools, featuring a phishing URL analyzer (PhishGuard) and an advanced reverse shell generator (ShellGen). This project combines a professional, hacker-themed UI with practical, self-contained security utilities.
🚀 Live Demo

You can view the live frontend of the website here:

https://hckn1l.github.io/PhishGuard/

    Note: The live demo showcases the full user interface for both tools.

        The Attacker (ShellGen) tool is fully functional on the live site.

        For the Defense (PhishGuard) tool to work, the Python backend must be running on your local machine. Please follow the steps below to run the full application.

✨ Features

    Dual-Mode Interface: Seamlessly switch between the blue-themed Defense tool and the red-themed Attacker tool.

    Hacker-Themed UI: A professional design featuring a glitch-effect title, an animated particle background, and glowing, interactive elements.

    Fully Self-Contained: The PhishGuard backend runs locally, requiring no external API keys. The ShellGen is pure JavaScript.

    Responsive Design: The interface is designed to work smoothly on all devices.

🛠️ Tools Included
🛡️ PhishGuard (Defense)

A powerful scanner to analyze and detect phishing & malicious URLs.

    Local Analysis Engine: Uses a rule-based scoring system to evaluate links.

    Detailed Results: Provides a risk score, a point-by-point analysis, and a clear recommendation.

    No API Keys Needed: Works entirely offline for privacy and ease of use.

⚔️ ShellGen (Attacker)

An advanced generator for creating one-line reverse shells.

    Multiple Shell Types: Supports common shells like Bash, Python, PHP, PowerShell, and Netcat.

    Dynamic Generation: The command is updated in real-time as you type.

    "Typing" Animation: For a dynamic, hacker-like feel.

    One-Click Copy: Instantly copy the generated payload to your clipboard.

⚙️ How to Run the Full Application Locally

To use the PhishGuard URL scanning functionality, you need to run the Python backend on your computer.
Prerequisites

    Python 3.x installed on your system.

    pip for installing Python packages.

1. Clone the Repository

git clone https://github.com/HckN1L/PhishGuard.git
cd PhishGuard

2. Install Dependencies

Install the required Python libraries.

pip install -r requirements.txt

3. Run the Backend Server

Start the Flask backend server.

python app.py

This will start the server on your local machine. Keep this terminal window open.
4. Use the Live Site

Now, open the live website: https://hckn1l.github.io/PhishGuard/. With the backend running on your machine, the PhishGuard scanner will now work as intended.
❤️ Credits

This project was created and designed by @HckN1L.
