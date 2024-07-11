import os
import asyncio
import aiohttp
import pandas as pd
import ipaddress
from art import text2art  # Importing the art library

# Constants
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
TXT_FILE_PATH = 'ips.txt'
OUTPUT_FILE_PATH_TXT = 'results.txt'
OUTPUT_FILE_PATH_CSV = 'results.csv'
IPSUM_BASE_URL = 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/'  # Base URL for IPsum lists

def display_welcome_message():
    """Display a welcome message using ASCII art."""
    print(text2art("IP Scanner", font='block'))
    print("Launching the OLNG SOC IP Scanner Tool!")
    print("This tool checks IP addresses against AbuseIPDB and IPsum lists.\n")

def read_ips_from_file(file_path):
    """Read IP addresses from a file and validate them."""
    with open(file_path, 'r') as file:
        ips = [line.strip() for line in file.readlines()]
        valid_ips = [ip for ip in ips if validate_ip(ip)]
        return valid_ips

def validate_ip(ip):
    """Validate an IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        print(f"Invalid IP address: {ip}")
        return False

async def fetch_ipsum_list(level):
    """Fetch the list of bad IPs from IPsum for the given level."""
    url = f'{IPSUM_BASE_URL}{level}.txt'
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            response.raise_for_status()
            text = await response.text()
            return set(line.strip() for line in text.splitlines() if line.strip() and not line.startswith('#'))

async def check_ip_abuse(session, ip, api_key):
    """Check the abuse confidence score of an IP using the AbuseIPDB API."""
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
    }
    if api_key:
        headers['Key'] = api_key

    try:
        async with session.get(ABUSEIPDB_URL, headers=headers, params=querystring) as response:
            if response.status != 200:
                error_detail = await response.text()
                print(f"Error checking IP {ip}: {response.status} - {error_detail}")
            else:
                return await response.json()
    except aiohttp.ClientResponseError as e:
        print(f"HTTP Error checking IP {ip}: {e.status} - {e.message}")
        return None

async def scan_ips(ips, api_key, level=None):
    """Scan IPs against the AbuseIPDB or IPsum lists."""
    results = []
    bad_ip_count = 0

    async with aiohttp.ClientSession() as session:
        if api_key:
            tasks = [asyncio.create_task(check_ip_abuse(session, ip, api_key)) for ip in ips]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for ip, response in zip(ips, responses):
                if isinstance(response, Exception):
                    print(f"Error checking IP {ip}: {response}")
                else:
                    abuse_confidence_score = response['data']['abuseConfidenceScore'] if response else 'N/A'
                    if abuse_confidence_score != 'N/A':
                        bad_ip_count += 1
                    results.append({'ip': ip, 'abuseConfidenceScore': abuse_confidence_score, 'levels': [level] if level else []})
                    print(f"IP: {ip} checked with AbuseIPDB. Abuse Confidence Score: {abuse_confidence_score}")
        else:
            if level is not None:
                ipsum_ips = await fetch_ipsum_list(level)
                for ip in ips:
                    if ip in ipsum_ips:
                        abuse_confidence_score = round((level / 8) * 100, 2)  # Estimate score based on level
                        results.append({'ip': ip, 'abuseConfidenceScore': abuse_confidence_score, 'levels': [level]})
                        bad_ip_count += 1
                        print(f"IP: {ip} found in IPsum level {level}. Estimated score: {abuse_confidence_score}")

    return results, bad_ip_count

def write_results_to_file(results, file_path, file_format):
    """Write the results to an output file."""
    if file_format == 'txt':
        with open(file_path, 'w') as file:
            file.write(f"{'IP Address':<20}{'Confidence Score':<20}{'Levels':<15}\n")
            file.write(f"{'-'*55}\n")
            for result in results:
                levels = ', '.join(map(str, result['levels']))
                file.write(f"{result['ip']:<20}{result['abuseConfidenceScore']:<20}{levels:<15}\n")
    elif file_format == 'csv':
        df = pd.DataFrame(results)
        df['levels'] = df['levels'].apply(lambda x: ', '.join(map(str, x)))
        df.to_csv(file_path, index=False)

async def main():
    """Main function to read IPs, check against IPsum and AbuseIPDB, and write results."""
    display_welcome_message()
    
    while True:
        api_key_input = input("Do you have an AbuseIPDB API key? Paste it if yes or type 'No': ").strip().lower()
        if api_key_input in ('no', 'n'):
            api_key = None
            break
        elif api_key_input:
            api_key = api_key_input
            break
        else:
            print("Invalid input. Please enter a valid API key or type 'No'.")

    ips = read_ips_from_file(TXT_FILE_PATH)
    all_results = {}
    level = 1
    previous_bad_ip_count = -1

    while level <= 8 and not api_key:
        print(f"\nScanning with IPsum level {level}...")
        results, bad_ip_count = await scan_ips(ips, api_key, level)
        if bad_ip_count == 0 and previous_bad_ip_count == 0:
            print(f"No IPs found in level {level}. Stopping the scan.")
            break
        previous_bad_ip_count = bad_ip_count
        for result in results:
            ip = result['ip']
            if ip in all_results:
                all_results[ip]['levels'].append(level)
                all_results[ip]['abuseConfidenceScore'] = max(all_results[ip]['abuseConfidenceScore'], result['abuseConfidenceScore'])
            else:
                all_results[ip] = result

        print(f"\nTotal bad IPs found with level {level}: {bad_ip_count}")
        level += 1

    if api_key:
        print("\nScanning with AbuseIPDB...")
        results, bad_ip_count = await scan_ips(ips, api_key)
        for result in results:
            ip = result['ip']
            if ip in all_results:
                all_results[ip]['levels'].append('AbuseIPDB')
                all_results[ip]['abuseConfidenceScore'] = max(all_results[ip]['abuseConfidenceScore'], result['abuseConfidenceScore'])
            else:
                result['levels'] = ['AbuseIPDB']
                all_results[ip] = result

    file_format = input("Enter the output file format (txt/csv): ").strip().lower()
    results_list = list(all_results.values())
    if file_format == 'txt':
        write_results_to_file(results_list, OUTPUT_FILE_PATH_TXT, file_format)
        print(f"Results written to {OUTPUT_FILE_PATH_TXT}")
    elif file_format == 'csv':
        write_results_to_file(results_list, OUTPUT_FILE_PATH_CSV, file_format)
        print(f"Results written to {OUTPUT_FILE_PATH_CSV}")
    else:
        print("Invalid file format. No results were saved.")

if __name__ == "__main__":
    asyncio.run(main())
