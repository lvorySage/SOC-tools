import aiohttp
import asyncio
import ipaddress
import os



# ur boy's constants
API_URL = "https://www.virustotal.com/api/v3/"
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
HEADERS = {
    "x-apikey": API_KEY
}

async def check_ip_VT(session, ip, api_key):
    # This function checks the IP address against the VirusTotal API
    url = f"{API_URL}ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key
    }
    try:
        async with session.get(url, headers=headers) as response:
            if response.status != 200:
                error_detail = await response.text()
                print(f"Error checking IP {ip}: {response.status} - {error_detail}")
                return None
            return await response.json()
    except aiohttp.ClientResponseError as e:
        print(f"HTTP Error checking IP {ip}: {e.status} - {e.message}")
        return None