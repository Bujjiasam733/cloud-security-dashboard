import argparse
import sys
from scanner import scan_account
from report import print_banner, print_results, save_report

def parse_arguments():
    parser = argparse.ArgumentParser(description="Cloud Security Posture Dashboard")
    parser.add_argument(
        "-s", "--save",
        action="store_true",
        help="Save audit report as JSON to reports/"
    )
    return parser.parse_args()

def main():
    print_banner()
    args = parse_arguments()
    print("  Scanning AWS account...\n")
    data = scan_account()
    print_results(data)
    if args.save:
        save_report(data)
    print("\n  Done.\n")

if __name__ == "__main__":
    main()