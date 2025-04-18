# totp_generator.py
import pyotp
import time
import argparse
import sys
from datetime import datetime

class TOTPGenerator:
    def __init__(self, secret):
        self.secret = secret
        self.totp = pyotp.TOTP(secret)
        
    def get_current_code(self):
        """Get current TOTP code"""
        return self.totp.now()
    
    def get_time_remaining(self):
        """Get remaining time until code expires"""
        return 60 - (int(time.time()) % 60)
    
    def watch_mode(self):
        """Continuously display TOTP codes with countdown"""
        try:
            while True:
                code = self.get_current_code()
                remaining = self.get_time_remaining()
                
                # Clear line and print new code with timestamp
                print(f"\r{datetime.now().strftime('%H:%M:%S')} | "
                      f"Code: {code} | "
                      f"Expires in: {remaining:02d}s", end="")
                
                if remaining == 0:
                    print()  # New line for new code
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n\nTOTP Generator stopped.")

def validate_secret(secret):
    """Validate if the secret is a valid base32 string"""
    try:
        pyotp.TOTP(secret).now()
        return True
    except Exception:
        return False

def main():
    parser = argparse.ArgumentParser(description='TOTP Code Generator')
    parser.add_argument('secret', help='TOTP secret key')
    parser.add_argument('-w', '--watch', 
                       action='store_true', 
                       help='Watch mode: continuously display codes')
    args = parser.parse_args()

    # Validate secret
    if not validate_secret(args.secret):
        print("Error: Invalid TOTP secret key")
        sys.exit(1)

    generator = TOTPGenerator(args.secret)

    if args.watch:
        print("=== TOTP Code Generator (Watch Mode) ===")
        print("Press Ctrl+C to stop")
        print("\nTime     | Current Code | Remaining Time")
        print("-" * 40)
        generator.watch_mode()
    else:
        code = generator.get_current_code()
        remaining = generator.get_time_remaining()
        print(f"\nCurrent TOTP Code: {code}")
        print(f"Code expires in: {remaining} seconds")

if __name__ == "__main__":
    main()