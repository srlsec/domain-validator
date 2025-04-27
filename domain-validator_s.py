import aiohttp
import random
import string
import json
import asyncio
import re
import os, sys
import os, platform, datetime, time, warnings, sys
from tqdm import tqdm


home_dir = os.path.expanduser("~")

# Define the mapping at the top of your script
RECORD_TYPE_CODES = {
    "A": 1,
    "AAAA": 28,
    "TXT": 16,
    "NS": 2,
    "CNAME": 5,
    "MX": 15
}


if len(sys.argv) < 3:
    print("Error: No input file provided.")
    print("Usage  : domain-validator <input_file> <domain_name>")
    print("Example: domain-validator resolved-all-domains.txt facebook.com")
    sys.exit(1)

subdomains_file = sys.argv[1]
output_file = sys.argv[2]
target_domain = sys.argv[3]




# Banner
def banner():
    # https://patorjk.com/software/taag/#p=testall&f=Graffiti&t=cobratoxin
    banner="""
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |D|O|M|A|I|N|-|V|A|L|I|D|A|T|O|R|  by srlsec
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
    print(banner)

async def cloudflare_processing(subdomains, parallel_limit=20):
    DNS_API_URL = "https://cloudflare-dns.com/dns-query"

    async def query_dns_records(session, subdomain, record_type):
        try:
            async with session.get(DNS_API_URL, params={'name': subdomain, 'type': record_type}, headers={'Accept': 'application/dns-json'}) as response:
                if response.status == 200:
                    raw_response = await response.text()
                    try:
                        result = json.loads(raw_response)
                        has_answer = "Answer" in result
                        answers = result.get("Answer", []) if has_answer else []
                        if answers:
                            first_answer_type = answers[0].get("type")
                            first_record_type = next(
                                (rtype for rtype, code in RECORD_TYPE_CODES.items() if code == first_answer_type), None
                            )
                            return bool(answers), answers, first_record_type
                        return False, [], None
                    except json.JSONDecodeError:
                        return False, [], None
        except Exception:
            return False, [], None

    async def wildcard_check(session, subdomain, record_type):
        try:
            record_type_code = RECORD_TYPE_CODES.get(record_type.upper())
            if not record_type_code:
                return False, None

            valid_base, base_answers, base_actual_type = await query_dns_records(session, subdomain, record_type)
            if not valid_base or not base_answers:
                return False, None

            parts = subdomain.split('.')
            pattern_tests = []

            for i in range(len(parts) - 1):
                test_parts = parts.copy()
                test_parts[i] = ''.join(random.choices(string.ascii_lowercase, k=10))
                pattern_tests.append('.'.join(test_parts))

            for test_subdomain in pattern_tests:
                valid_garbage, garbage_answers, garbage_actual_type = await query_dns_records(session, test_subdomain, record_type)
                if valid_garbage and base_actual_type == garbage_actual_type:
                    return True, base_actual_type

            return False, None
        except Exception:
            return False, None

    async def process_subdomain(session, subdomain, semaphore, progress_bar):
        async with semaphore:
            record_types = ["A", "AAAA", "NS", "CNAME", "TXT", "MX"]
            try:
                for record_type in record_types:
                    has_records, _, actual_type = await query_dns_records(session, subdomain, record_type)
                    if has_records:
                        is_wildcard, wildcard_type = await wildcard_check(session, subdomain, record_type)
                        if is_wildcard:
                            result = (subdomain, False, f"wildcard_{wildcard_type}")
                        else:
                            result = (subdomain, True, None)
                        break
                else:
                    result = (subdomain, False, "no_records")
            except Exception:
                result = (subdomain, False, "error")

            progress_bar.update(1)  # Update progress bar
            return result

    async def process_subdomains(subdomains):
        semaphore = asyncio.Semaphore(parallel_limit)
        valid_subs = []
        invalid_subs = []
        invalid_reasons = {}

        async with aiohttp.ClientSession() as session:
            with tqdm(total=len(subdomains), desc="", unit="sub", ncols=80) as progress_bar:
                tasks = [process_subdomain(session, sub, semaphore, progress_bar) for sub in subdomains]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, tuple):
                        subdomain, is_valid, reason = result
                        if is_valid:
                            valid_subs.append(subdomain)
                        else:
                            invalid_subs.append(subdomain)
                            invalid_reasons[subdomain] = reason

        return valid_subs, invalid_subs, invalid_reasons

    return await process_subdomains(subdomains)


def main():
    if os.path.exists(output_file):
        print(f"Output file '{output_file}' already exists. Skipping scan.")
        sys.exit(0)  # Exit without scanning

    try:
        if subdomains_file == "-":
            lines = [line.strip() for line in sys.stdin if line.strip()]
        else:
            with open(subdomains_file) as f:
                lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading input: {e}")
        sys.exit(1)

    if not lines:
        print("No subdomains found in file")
        exit(1)

    subdomains = set()
    for line in lines:
        
        cleaned_line = re.sub(r'^[a-zA-Z]+://', '', line)
        cleaned_line = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', cleaned_line)
        cleaned_line = re.sub(r'[^a-zA-Z0-9._-]', '', cleaned_line)
        cleaned_line = cleaned_line.strip().lower().lstrip('.')

        if not cleaned_line or cleaned_line == target_domain or not cleaned_line.endswith("." + target_domain):
            continue
        subdomains.add(cleaned_line)

    if not subdomains:
        print("No valid subdomains found after preprocessing")
        exit(1)

    print(f"\nProcessing {len(subdomains)} unique subdomains...\n")

    valid_subs, invalid_subs, invalid_reasons = asyncio.run(
        cloudflare_processing(list(subdomains), parallel_limit=50)
    )


    print(f"\nTotal valid subdomains: {len(valid_subs)}")
    print(f"Total invalid subdomains: {len(invalid_subs)}")

    # Save valid subdomains to a file
    with open(output_file, "w") as f:
        for sub in valid_subs:
            f.write(sub + "\n")

    print(f"\nValid subdomains saved to {output_file}")


if __name__ == "__main__":
    try :
        start = time.time()
        banner()

        print(datetime.datetime.now().strftime( "================ STARTED - %d/%m/%Y %H:%M:%S 00:00:00:00 ================") + '\n')

        main()
        
        now = datetime.datetime.now()
        end = time.time()
        hours, rem = divmod(end-start, 3600)
        minutes, seconds = divmod(rem, 60)

        print(now.strftime('\n' + "=============== COMPLETED - %d/%m/%Y %H:%M:%S")+  " {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds)  + ' ===============' + '\n')

    except KeyboardInterrupt:
        print(f'\nKeyboard Interrupt.\n')
        sys.exit(130)
