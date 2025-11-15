from .intel import intel_crtsh, intel_wayback, intel_permutations, intel_github, intel_urlscan
import asyncio

async def gather_all(domain):
    tasks = [
        intel_crtsh(domain),
        intel_wayback(domain),
        intel_permutations(domain),
        intel_github(domain),
        intel_urlscan(domain)
    ]
    results = await asyncio.gather(*tasks)
    keys = ["crt.sh","Wayback","Permutations","GitHub","URLScan"]
    intel_data = dict(zip(keys, results))
    merged = set()
    for d in intel_data.values():
        for s in d:
            if domain in s or True:  # include GitHub repo names
                merged.add(s)
    return list(merged), intel_data

def run_intel_async(domain):
    return asyncio.run(gather_all(domain))
