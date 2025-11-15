import sys
import argparse
from reconx.banner import banner
from reconx.intel_engine import run_intel_async

def print_help():
    print("""
Usage: reconx <command> [options]

  -h          Show the program usage message
  --help      Show the program usage message
  --version   Print the Recon X version information

Subcommands:

    reconx intel    - Discover domains & assets using passive intelligence sources
    reconx enum     - Perform passive enumeration and network mapping
""")

def intel_command(args):
    parser = argparse.ArgumentParser(
        usage="reconx intel -d <domain> [options]"
    )
    parser.add_argument("-d", required=True, help="Target domain")
    parser.add_argument("-o", default="intel.txt", help="Output file")
    parsed = parser.parse_args(args)

    banner()
    print(f"[*] Performing intel gathering on: {parsed.d}\n")
    merged, raw = run_intel_async(parsed.d)

    for src, data in raw.items():
        print(f"\n[+] {src} results ({len(data)}):")
        for item in data:
            print(f"    {item}")

    with open(parsed.o, "w") as f:
        for sub in merged:
            f.write(sub + "\n")
    print(f"\n[✔] Intel completed. Saved to {parsed.o}")

def enum_command(args):
    parser = argparse.ArgumentParser(
        usage="reconx enum -d <domain> [options]"
    )
    parser.add_argument("-d", required=True, help="Target domain")
    parser.add_argument("-o", default="enum.txt", help="Output file")
    parsed = parser.parse_args(args)

    banner()
    print(f"[*] Performing enumeration on: {parsed.d}\n")
    merged, raw = run_intel_async(parsed.d)

    for src, data in raw.items():
        print(f"\n[+] {src} results ({len(data)}):")
        for item in data:
            print(f"    {item}")

    with open(parsed.o, "w") as f:
        for sub in merged:
            f.write(sub + "\n")
    print(f"\n[✔] Enumeration completed. Saved to {parsed.o}")

def main():
    if len(sys.argv) < 2:
        print_help()
        return

    cmd = sys.argv[1].lower()

    if cmd in ("-h","--help"):
        print_help()
    elif cmd == "intel":
        intel_command(sys.argv[2:])
    elif cmd == "enum":
        enum_command(sys.argv[2:])
    else:
        print_help()

if __name__ == "__main__":
    main()
