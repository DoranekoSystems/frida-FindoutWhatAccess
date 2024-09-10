# frida-FindoutWhatAccess

Implements 'Find out what accesses this address' using Frida.  
Tested on iOS arm64 only.

<img width="600" alt="image" src="https://github.com/user-attachments/assets/56e709b8-971a-4763-8608-478e8a711d64">

## Setup
1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## How to Use
1. Run the script with your target application:
```bash
python main.py SurvivalShooter # attach

or

python main.py com.DoranekoSystems.SurvivalShooter # spawn
```
