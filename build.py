import os
import sys
import subprocess

def build_executable():
    print("Building XanaTool executable...")
    
    # Install required packages
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    
    # Build the executable
    build_command = [
        "pyinstaller",
        "--onefile",
        "--windowed",
        "--name", "XanaTool",
        "--add-data", "README.md;.",
        "--add-data", "LICENSE;.",
        "XanaTool.py"
    ]
    
    subprocess.run(build_command)
    
    print("\nBuild complete! The executable can be found in the 'dist' folder.")
    print("Remember to run it as administrator for full functionality.")

if __name__ == "__main__":
    build_executable() 