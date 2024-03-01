#!/usr/bin/python3

import json
import sys
import argparse
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser(
            prog=sys.argv[0],
            description="A tool for examining cookies set within a HAR file or the values of various headers"
            )

    subparser = parser.add_subparsers(title="operating mode", description="Accepts one of the following operating modes: cookie, header")

    # Cookie mode
    cookie_argparser = subparser.add_parser("cookie", help="Examine cookies")
    cookie_argparser.set_defaults(func=cookie_mode)
    cookie_argparser.add_argument("filename")
    cookie_argparser.add_argument("--httponly", "-ho", action="store_true", help="Print the 'httponly' value of set cookies.", default=False)
    cookie_argparser.add_argument("--secure", "-se", action="store_true", help="Print the 'secure' value of set cookies.", default=False)
    cookie_argparser.add_argument("--samesite", "-ss", action="store_true", help="Print the 'samesite' value of set cookies.", default=False)
    cookie_argparser.add_argument("-v", "--verbose", action='count', help="produce more verbose output", default=0, required=False)
    cookie_argparser.add_argument("--all", "-a", action="store_true", help="Print all attributes of set cookies.", default=False)


    # Header mode
    header_argparser = subparser.add_parser("header", help="Examine headers")
    header_argparser.set_defaults(func=header_mode)
    header_argparser.add_argument("filename")
    header_argparser.add_argument("header_name", type=str.lower)
    header_argparser.add_argument("-v", "--verbose", action='count', help="produce more verbose output", default=0, required=False)

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)

def cookie_mode(args):
    # If none of the cookie flags are set, default them all to true
    if not (args.httponly or args.secure or args.samesite) or args.all:
        args.samesite = True
        args.secure = True
        args.httponly = True

    json_content = read_file(args.filename)
    cookie_map = {"httponly":defaultdict(set),"secure":defaultdict(set),"samesite":defaultdict(set)}
    for entry in json_content["log"]["entries"]:
        set_cookie_values = [header["value"] for header in entry["response"]["headers"] if header["name"].lower() == "set-cookie"]
        for cookie in set_cookie_values:
            cookie_namevalue = cookie.split(";",1)[0]
            cookie_attrs = [attr.replace(' ', '').lower() for attr in cookie.split(";")[1:]]
            if args.verbose < 3:
                cookie_namevalue = cookie_namevalue.split('=',1)[0]

            if args.httponly:
                cookie_map["httponly"]["httponly" in cookie_attrs].add(cookie_namevalue)

            if args.secure:
                cookie_map["secure"]["secure" in cookie_attrs].add(cookie_namevalue)

            if args.samesite:
                if "samesite=none" in cookie_attrs:
                    cookie_map["samesite"]["none"].add(cookie_namevalue)
                elif "samesite=strict" in cookie_attrs:
                    cookie_map["samesite"]["strict"].add(cookie_namevalue)
                elif "samesite=lax" in cookie_attrs and args.verbose < 2:
                    # Most browsers default to Lax on unset cookies
                    cookie_map["samesite"]["lax"].add(cookie_namevalue)
                else:
                    # Show unset cookies for verbose output
                    cookie_map["samesite"]["unset"].add(cookie_namevalue)
    if args.secure:
        print("Secure")
        print_cookie_map("Secure", cookie_map["secure"], args.verbose)
    if args.samesite:
        print("SameSite")
        print_cookie_map("SameSite", cookie_map["samesite"], args.verbose)
    if args.httponly:
        print("HTTPonly")
        print_cookie_map("HTTPonly", cookie_map["httponly"], args.verbose)

    


def header_mode(args):
    json_content = read_file(args.filename)
    header_url_map = defaultdict(set)
    for entry in json_content["log"]["entries"]:
        header_values = [header["value"] for header in entry["response"]["headers"] if header["name"].lower() == args.header_name]
        for value in header_values:
            url_value = ""
            if args.verbose >= 2:
                url_value = entry["request"]["url"]
            else:
                url_value = entry["request"]["url"].split("?")[0]
            header_url_map[value].add(url_value)
    
    print_url_map(args.header_name, header_url_map, args.verbose)
    


def read_file(filename):
    f = open(filename, "r")
    file_content = json.loads(f.read())
    f.close()
    return file_content

def print_url_map(item_name, url_map, verbose=0):
    for value in url_map.keys():
        print("{0}: {1}".format(item_name, value))
        if verbose:
            print("\n".join(['\t' + item for item in url_map[value]]))
        else:
            print("{0} URLs".format(len(url_map[value])))

def print_cookie_map(attr_name, cookie_map, verbose=0):
    for value in cookie_map.keys():
        print("\t{0}: {1}".format(attr_name, value))
        if verbose:
            print("\n".join(['\t'*2 + cookie_name for cookie_name in cookie_map[value]]))
        else:
            print('\t' * 2 + "{0} cookies".format(len(cookie_map[value])))


if __name__=="__main__":
    main()
