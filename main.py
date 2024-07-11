import os
import asyncio
import aiohttp
import pandas as pd

# Constants
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
TXT_FILE_PATH = 'ips.txt'
OUTPUT_FILE_PATH_TXT = 'results.txt'
OUTPUT_FILE_PATH_CSV = 'results.csv'
IPSUM_BASE_URL = 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/'  # Base URL for IPsum lists

def read_ips_from_file(file_path):
    """Read IP addresses from a file."""
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

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

    async with session.get(ABUSEIPDB_URL, headers=headers, params=querystring) as response:
        response.raise_for_status()
        return await response.json()

async def scan_ips(level, ips, api_key):
    """Scan IPs against the IPsum list and AbuseIPDB."""
    ipsum_ips = await fetch_ipsum_list(level)
    results = []
    bad_ip_count = 0

    async with aiohttp.ClientSession() as session:
        tasks = []
        for ip in ips:
            if ip in ipsum_ips:
                abuse_confidence_score = 'N/A'
                if not api_key:
                    abuse_confidence_score = round((level / 8) * 100, 2)  # Estimate score based on level
                results.append({'ip': ip, 'abuseConfidenceScore': abuse_confidence_score, 'level': level})
                bad_ip_count += 1
                print(f"IP: {ip} found in IPsum level {level}. Estimated score: {abuse_confidence_score}")
            elif api_key:
                tasks.append(asyncio.create_task(check_ip_abuse(session, ip, api_key)))
        
        if api_key:
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for ip, response in zip(ips, responses):
                if isinstance(response, Exception):
                    print(f"Error checking IP {ip}: {response}")
                else:
                    abuse_confidence_score = response['data']['abuseConfidenceScore']
                    if abuse_confidence_score != 'N/A':
                        bad_ip_count += 1
                    results.append({'ip': ip, 'abuseConfidenceScore': abuse_confidence_score, 'level': level})
                    print(f"IP: {ip} checked with AbuseIPDB. Abuse Confidence Score: {abuse_confidence_score}")

    return results, bad_ip_count

def write_results_to_file(results, file_path, file_format):
    """Write the results to an output file."""
    if file_format == 'txt':
        with open(file_path, 'w') as file:
            file.write(f"{'IP Address':<20}{'Confidence Score':<20}{'IPsum Level':<15}\n")
            file.write(f"{'-'*55}\n")
            for result in results:
                if result['abuseConfidenceScore'] != 'N/A':
                    file.write(f"{result['ip']:<20}{result['abuseConfidenceScore']:<20}{result['level']:<15}\n")
    elif file_format == 'csv':
        df = pd.DataFrame(results)
        df.to_csv(file_path, index=False)

async def main():
    """Main function to read IPs, check against IPsum and AbuseIPDB, and write results."""
    api_key = input("Do you have an AbuseIPDB API key? Paste it if yes or type 'No': ").strip()
    if api_key.lower() == 'no':
        api_key = None

    ips = read_ips_from_file(TXT_FILE_PATH)
    all_results = []
    level = 1

    while level <= 8:
        print(f"\nScanning with IPsum level {level}...")
        results, bad_ip_count = await scan_ips(level, ips, api_key)
        all_results.extend(results)

        print(f"\nTotal bad IPs found with level {level}: {bad_ip_count}")
        continue_scanning = input("Do you want to continue scanning with the next level? (yes/no): ").strip().lower()

        if continue_scanning != 'yes':
            break

        level += 1

    file_format = input("Enter the output file format (txt/csv): ").strip().lower()
    if file_format == 'txt':
        write_results_to_file(all_results, OUTPUT_FILE_PATH_TXT, file_format)
        print(f"Results written to {OUTPUT_FILE_PATH_TXT}")
    elif file_format == 'csv':
        write_results_to_file(all_results, OUTPUT_FILE_PATH_CSV, file_format)
        print(f"Results written to {OUTPUT_FILE_PATH_CSV}")
    else:
        print("Invalid file format. No results were saved.")

if __name__ == "__main__":
    asyncio.run(main())
