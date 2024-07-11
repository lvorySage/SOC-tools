#SOC-tools
# IP Scanner Script

This Python script reads IP addresses from a file, checks them against IPsum lists which is another git hub repo that gets updated daily, and uses the AbuseIPDB API to determine their abuse confidence scores. The results are saved in either a text or CSV file.

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

4. **Set up your API key**:
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
python main.py default name of the script that you will have to run is "main.py"

# On macOS/Linux
python3 main.py


## future updates 

1. **features that will be added in the next commits:** 


- Prompt for the API Key:
- Add a prompt at the beginning of the script to ask the user if they have an API key.

- Estimate Severity or Trust Score:
- If the user does not provide an API key, add a simple heuristic to estimate the severity or trust score based on IPsum levels.

- Verbose Results:
- Modify the script to only display IPs found in the lookups and indicate each level in the results file.





 # v 0.0.1 update and improvements#

 Summary of Changes

    - Prompt for API Key: The script now prompts the user to provide an API key or type 'No' if they don't have one.
    - Estimation of Severity: If the API key is not provided, the script estimates the abuse confidence score based on the IPsum level.
    - Verbose Results: The script only prints IPs that are found in the lookups.
    - Result Indication by Level: Each level of lookup is indicated in the results file before listing the IPs found at that level.




    Myore improvements :
    if the user does not provide an API key, the script does not attempt to connect to the AbuseIPDB API. Additionally, the script now estimates the abuse confidence score based on the IPsum level if the API key is not supplied.

- Skipping API Calls if No API Key: The script now checks if an API key is provided before attempting to connect to the AbuseIPDB API. If no API key is provided, it estimates the abuse confidence score based on the IPsum level.
- Verbose Output: The script now only prints IPs that are found in the lookups.
- Estimated Scores: The script assigns an estimated score based on the IPsum level if no API key is provided.





    Yet more improvments: 

    - Formatting Results:
        Results are formatted in a tabular format for better readability.
        The write_results_to_file function ensures that only the IPs that match the criteria are written to the results file.
    - Estimated Scores:
        Estimated abuse confidence scores are rounded to two decimal places.
    - Output Headers:
        The results file includes headers to make it easier to understand the information provided.
This should result in a neatly formatted output that a SOC analyst can quickly review to determine which IPs need to be blocked or further investigated.




part 2 

- Formatting Output:

    The results file is formatted in a neat tabular format for better readability.
    Only IPs with a valid confidence score or those found in IPsum are included in the results.

- Score Calculation:

    If no API key is provided, the abuse confidence score is estimated based on the level, where higher levels indicate a higher confidence score (e.g., level 1 = 12.5, level 8 = 100).


part 3 the script dosn't print out the expected 

- Ensure Correct URL for IPsum List:

    'Confirm' the base URL and fetch URL are correct.

- Fix Results Collection:

    'Add' an 'in_ipsum' field to differentiate IPs found in IPsum from those checked via AbuseIPDB.

- Write Only Relevant Results:

    'Ensure' only relevant IPs (those found) are written to the output file.

- Verbose Printing:

    'Only' print matching IPs to the terminal.