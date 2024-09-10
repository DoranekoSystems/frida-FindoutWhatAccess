# Frida - FindOutWhatAccess

This project implements the functionality of 'Find out what accesses this address' using Frida.

## Setup
1. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## How to Use
1. Modify `main.py` to set watchpoints for the desired memory addresses. For example:
    ```python
    api.setwatchpoint(0xb9cd26b10, 4, "w")  # Watch for writes
    api.setwatchpoint(0xb9cd26b18, 4, "r")  # Watch for reads
    ```

2. Run the script with your target application:
    ```bash
    python main.py SurvivalShooter
    ```

## Todo
- Implement functionality to identify the watchpoint number triggered by memory access.
- Add a graphical user interface (GUI) for easier interaction.
