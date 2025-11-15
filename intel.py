import aiohttp
import asyncio

async def fetch_json(session, url, headers=None):
    try:
        async with session.get(url, headers=headers, timeout=10) as resp:
            return await resp.json()
    except:
        return []

async def intel_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    async with aiohttp.ClientSession() as session:
        data = await fetch_json(session, url)
        subs = set()
        for d in data:
            subs.update(d.get("name_value", "").split("\n"))
        return list(subs)

async def intel_wayback(domain):
    url = f"http://web.archive.org/cdx/search?url=*.{domain}/*&output=json&collapse=urlkey"
    async with aiohttp.ClientSession() as session:
        data = await fetch_json(session, url)
        hosts = set()
        for e in data[1:]:
            url = e[2]
            host = url.split("/")[2]
            if domain in host:
                hosts.add(host)
        return list(hosts)

async def intel_permutations(domain):
    prefixes = ["dev","api","staging","test","qa","beta"]
    return [f"{p}.{domain}" for p in prefixes]

async def intel_github(domain):
    url = f"https://api.github.com/search/code?q={domain}"
    async with aiohttp.ClientSession() as session:
        data = await fetch_json(session, url)
        subs = set()
        for item in data.get("items", []):
            repo = item.get("repository", {}).get("full_name", "")
            if repo:
                subs.add(repo)
        return list(subs)

async def intel_urlscan(domain):
    url = "https://urlscan.io/api/v1/search/"
    async with aiohttp.ClientSession() as session:
        params = {"q": domain}
        data = await fetch_json(session, url)
        subs = set()
        for res in data.get("results", []):
            host = res.get("task", {}).get("domain", "")
            if domain in host:
                subs.add(host)
        return list(subs)
