
import os
import subprocess

class NetworkDiagnosticAgent:
    def __init__(self):
        pass

    def run_ping(self, target):
        
        
        print(f"[*] Running diagnostics for host: {target}")
        
        # VULNERABILITY: Command Injection
        # On Windows: target could be "127.0.0.1 & echo hacked > hacked.txt"
       
        command = f"ping -n 1 {target}" # -n 1 for Windows
        
        print(f"[!] Executing command: {command}")
        
        # Unsafe execution
        os.system(command)
        
        return "Diagnostic complete"

if __name__ == "__main__":
    agent = NetworkDiagnosticAgent()
    
    # Normal operation
    agent.run_ping("google.com")
    
    # Exploit demonstration (simulated for Windows)
    print("\n[!] Simulating command injection attack...")
    agent.run_ping("127.0.0.1 & echo '[VULNERABILITY DETECTED]' > pwned_diagnostic.txt & dir")
