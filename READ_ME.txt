# IP Scanner Script

This Python script reads IP addresses from a file, checks them against IPsum lists, and uses the AbuseIPDB API to determine their abuse confidence scores. The results are saved in either a text or CSV file.

## Prerequisites

- Python 3.6 or higher
- aiohttp
- pandas

## Setup

1. **Clone the repository**:
    ```sh
    git clone <repository_url>
    cd <repository_directory>
    ```

2. **Create a virtual environment**:
    - On Windows:
      ```sh
      python -m venv venv
      .\venv\Scripts\activate
      ```
    - On macOS/Linux:
      ```sh
      python3 -m venv venv
      source venv/bin/activate
      ```

3. **Install dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

4. **Set up your API key if you have one**:
    Replace `YOUR_API_KEY` in the script with your actual AbuseIPDB API key.

## Usage

1. **Prepare your input file**:
    - Create a file named `ips.txt` in the same directory as the script.
    - Add the IP addresses you want to check, one per line.

2. **Run the script**:
    ```sh
    python script_name.py
    ```

    Replace `script_name.py` with the name of your script file.

3. **Follow the prompts**:
    - The script will ask if you want to continue scanning with the next IPsum level after each level.
    - After the scanning process, it will ask for the desired output file format (txt/csv).
    - The results will be saved in `results.txt` or `results.csv` based on your choice.

## Example

```sh
# On Windows
python script_name.py

# On macOS/Linux
python3 script_name.py





# IP Scanner Script

This Python script reads IP addresses from a file, checks them against IPsum lists, and optionally uses the AbuseIPDB API to determine their abuse confidence scores. The results are saved in either a text or CSV file.

## Prerequisites

- Python 3.6 or higher
- aiohttp
- pandas

## Setup

1. **Clone the repository**:
    ```sh
    git clone <repository_url>
    cd <repository_directory>
    ```

2. **Create a virtual environment**:
    - On Windows:
      ```sh
      python -m venv venv
      .\venv\Scripts\activate
      ```
    - On macOS/Linux:
      ```sh
      python3 -m venv venv
      source venv/bin/activate
      ```

3. **Install dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. **Prepare your input file**:
    - Create a file named `ips.txt` in the same directory as the script.
    - Add the IP addresses you want to check, one per line.

2. **Run the script**:
    ```sh
    python script_name.py
    ```

    Replace `script_name.py` with the name of your script file.

3. **Follow the prompts**:
    - The script will ask if you have an AbuseIPDB API key. If you don't, type 'No'.
    - The script will ask if you want to continue scanning with the next IPsum level after each level.
    - After the scanning process, it will ask for the desired output file format (txt/csv).
    - The results will be saved in `results.txt` or `results.csv` based on your choice.

## Example

```sh
# On Windows
python script_name.py

# On macOS/Linux
python3 script_name.py
