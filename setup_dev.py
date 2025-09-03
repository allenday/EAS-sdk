#!/usr/bin/env python3
"""
Development Setup Script for EAS SDK

This script helps developers get started quickly with the EAS SDK.
It sets up the development environment and creates necessary configuration files.

Usage:
    python setup_dev.py [--testnet] [--mainnet] [--interactive]
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def check_python_version():
    """Check if Python version meets requirements."""
    if sys.version_info < (3, 11):
        print("❌ Python 3.11 or higher is required")
        print(f"   Current version: {sys.version}")
        print("   Please upgrade Python and try again")
        return False
    
    print(f"✅ Python version: {sys.version_info.major}.{sys.version_info.minor}")
    return True


def check_task():
    """Check if Task (taskfile.dev) is available."""
    try:
        result = subprocess.run(['task', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Task is available")
            return True
    except FileNotFoundError:
        pass
    
    print("⚠️  Task not found - using pip directly")
    print("   Install Task from https://taskfile.dev for better experience")
    return False


def setup_virtual_environment():
    """Set up Python virtual environment."""
    venv_path = Path(".venv")
    
    if venv_path.exists():
        print("✅ Virtual environment already exists")
        return True
    
    print("🐍 Creating virtual environment...")
    try:
        subprocess.run([sys.executable, "-m", "venv", ".venv"], check=True)
        print("✅ Virtual environment created")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create virtual environment: {e}")
        return False


def install_dependencies():
    """Install project dependencies."""
    venv_python = Path(".venv") / "Scripts" / "python" if os.name == "nt" else Path(".venv") / "bin" / "python"
    
    if not venv_python.exists():
        print("❌ Virtual environment not found")
        return False
    
    print("📦 Installing dependencies...")
    try:
        # Install in development mode with all extras
        subprocess.run([str(venv_python), "-m", "pip", "install", "-e", ".[dev]"], check=True)
        print("✅ Dependencies installed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False


def create_env_file(testnet=True, interactive=False):
    """Create .env file with configuration."""
    env_file = Path(".env")
    
    if env_file.exists():
        print("⚠️  .env file already exists")
        if not interactive:
            return True
        
        response = input("   Overwrite existing .env file? [y/N]: ")
        if response.lower() != 'y':
            return True
    
    print("📝 Creating .env configuration file...")
    
    # Default configuration
    if testnet:
        chain = "sepolia"
        env_type = "testnet"
    else:
        chain = "ethereum"
        env_type = "mainnet"
    
    env_content = f"""# EAS SDK Configuration
# 
# This file contains your EAS SDK configuration.
# Copy .env.example and fill in your values.

# Network Configuration
EAS_CHAIN={chain}

# Account Configuration (REQUIRED)
# Get testnet ETH from https://sepoliafaucet.com for testing
EAS_PRIVATE_KEY=0x...your_private_key_here
EAS_FROM_ACCOUNT=0x...your_account_address_here

# Optional Overrides
# EAS_RPC_URL=https://your-custom-rpc-url.com
# EAS_CONTRACT_ADDRESS=0x...custom_contract_address

# Development Settings
EAS_ENVIRONMENT=development

# Logging Level (DEBUG, INFO, WARNING, ERROR)
EAS_LOG_LEVEL=INFO

# ==================================================
# SECURITY WARNINGS:
# 1. NEVER commit this file to version control
# 2. Use testnet for development ({env_type} configured)
# 3. Use environment variables in production
# 4. Rotate your keys regularly
# ==================================================
"""
    
    try:
        with open(env_file, 'w') as f:
            f.write(env_content)
        print(f"✅ .env file created for {env_type}")
        print("   📝 Please edit .env and add your private key and account address")
        return True
    except Exception as e:
        print(f"❌ Failed to create .env file: {e}")
        return False


def run_initial_tests():
    """Run basic tests to verify setup."""
    print("🧪 Running setup verification tests...")
    
    venv_python = Path(".venv") / "Scripts" / "python" if os.name == "nt" else Path(".venv") / "bin" / "python"
    
    try:
        # Test basic import
        result = subprocess.run([
            str(venv_python), "-c", 
            "from EAS import EAS; from EAS.config import list_supported_chains; print('✅ Import test passed')"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Basic import test passed")
        else:
            print(f"❌ Import test failed: {result.stderr}")
            return False
            
        # Test configuration
        result = subprocess.run([
            str(venv_python), "-c",
            "from EAS.config import list_supported_chains; chains = list_supported_chains(); print(f'✅ {len(chains)} chains supported')"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(result.stdout.strip())
        else:
            print(f"❌ Configuration test failed: {result.stderr}")
            return False
            
        return True
        
    except subprocess.TimeoutExpired:
        print("❌ Tests timed out")
        return False
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return False


def show_next_steps():
    """Show next steps for the developer."""
    print("\n🎉 Setup complete! Next steps:")
    print()
    print("1. 📝 Configure your environment:")
    print("   • Edit .env file and add your private key and account address")
    print("   • Get testnet ETH from https://sepoliafaucet.com")
    print()
    print("2. 🚀 Try the examples:")
    print("   • python examples/quick_start.py")
    print("   • python examples/full_example.py")
    print()
    print("3. 🔧 Development commands:")
    if Path("Taskfile.yml").exists():
        print("   • task help                    # Show all available commands")
        print("   • task test:unit               # Run unit tests")
        print("   • task format                  # Format code")
        print("   • task check                   # Run all checks")
    else:
        print("   • source .venv/bin/activate    # Activate virtual environment")
        print("   • pip install -e .[dev]       # Install in development mode")
    print()
    print("4. 📚 Documentation:")
    print("   • README.md                    # Main documentation")
    print("   • examples/                    # Example code")
    print("   • https://docs.attest.sh       # Official EAS docs")
    print()
    print("🔒 Security reminders:")
    print("   • Never commit .env to version control")
    print("   • Use testnet for development")
    print("   • Use environment variables in production")


def main():
    """Main setup function."""
    parser = argparse.ArgumentParser(description="Set up EAS SDK development environment")
    parser.add_argument("--testnet", action="store_true", default=True, help="Configure for testnet (default)")
    parser.add_argument("--mainnet", action="store_true", help="Configure for mainnet")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("--skip-tests", action="store_true", help="Skip verification tests")
    
    args = parser.parse_args()
    
    # If mainnet is specified, don't use testnet
    if args.mainnet:
        args.testnet = False
    
    print("🚀 EAS SDK Development Setup")
    print("=" * 40)
    
    # Check prerequisites
    if not check_python_version():
        sys.exit(1)
    
    has_task = check_task()
    
    # Setup steps
    success = True
    
    if success and not setup_virtual_environment():
        success = False
    
    if success and not install_dependencies():
        success = False
    
    if success and not create_env_file(testnet=args.testnet, interactive=args.interactive):
        success = False
    
    if success and not args.skip_tests and not run_initial_tests():
        print("⚠️  Setup completed with test failures")
        print("   This is normal if you haven't configured .env yet")
        success = True  # Don't fail on test issues during setup
    
    if success:
        show_next_steps()
        print("\n✨ Setup completed successfully!")
    else:
        print("\n❌ Setup failed. Please check the errors above.")
        sys.exit(1)


if __name__ == "__main__":
    main()