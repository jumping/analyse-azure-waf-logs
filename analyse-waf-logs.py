import argparse
import json
import os
import re


"""
Script to analyse Azure WAF Logs.
Written for Python3
Example execution: python3 analyse-waf-logs.py path/to/waf/logs
"""


def add_rule(results, descriptions, rule_id, description):
    """
    Add count and description relating to a triggered WAF rule.
    :param results: Dictionary storing the trigger count for each rule triggered.
    :param descriptions: Dictionary storing the rule description for each rule triggered.
    :param rule_id: The rule id that was triggered.
    :param description: The rule description.
    """
    try:
        total = results[rule_id]
        results[rule_id] = total + 1
    except:
        # Data for this rule_id doesn't exist yet.
        results[rule_id] = 1
        descriptions[rule_id] = description


def increment_client_count(client_ips, client_ip):
    """
    Count the WAF rules triggered by a client ip.
    :param client_ips: Dictionary storing the count of all rules triggered by a client id.
    :param client_ip: The client ip address.
    :return:
    """
    try:
        total = client_ips[client_ip]
        client_ips[client_ip] = total + 1
    except:
        # Data for this client_ip doesn't exist yet
        client_ips[client_ip] = 1


def find_log_files(root, regex):
    """
    Find all the WAF log files, starting at a root path.
    :param root: The system path that stores the WAF log files.
    :param regex: The regex to find the WAF files.
    :return: The List of found log files.
    """
    reg_obj = re.compile(regex)
    res = []
    for dirName, subdirList, fileList in os.walk(root):
        for fname in fileList:
            if reg_obj.match(os.path.join(dirName, fname)):
                res.append(os.path.join(dirName, fname))
    return res


def parse_log_file(results, descriptions, client_ips, path):
    """
    Parse a log file, which is made up of valid JSON blocks.  The file itself is not valid JSON.
    :param results: Dictionary storing the trigger count for each rule triggered.
    :param descriptions: Dictionary storing the rule description for each rule triggered.
    :param client_ips: Dictionary storing count of all rules triggered by a client id.
    :param path: The path of an individual WAF log file determined by year, month, day, hour and minute.
    """
    f = open(path, 'r')
    text = f.read()
    json_blocks = text.strip().split('}}\n')
    for json_block in json_blocks:

        json_block_fixed = json_block
        if not json_block_fixed.endswith('}}'):
            json_block_fixed = json_block + '}}'

        if len(json_block_fixed) > 4:
            try:
                parsed = json.loads(json_block_fixed)
                add_rule(results, descriptions, parsed['properties']['ruleId'], parsed['properties']['message'])
                increment_client_count(client_ips, parsed['properties']['clientIp'])
            except:
                print('Error', json_block_fixed)


def report_triggered_rules(results, descriptions):
    """
    Print the trigger count of each rule triggered.
    :param results: Dictionary storing the trigger count for each rule triggered.
    :param descriptions: Dictionary storing the rule description for each rule triggered.
    """
    print('rule id, description, count')
    s = [(k, results[k]) for k in sorted(results, key=results.get, reverse=True)]
    for k, v in s:
        description = descriptions[k]
        print(k + ',', description + ',', v)


def report_client_ips(client_ips):
    """
    Print the trigger count of each client ip that triggered rules.
    :param client_ips: Dictionary storing the count of all rules triggered by a client id.
    """
    print('\nclient ip, count')
    s = [(k, client_ips[k]) for k in sorted(client_ips, key=client_ips.get, reverse=True)]
    for k, v in s:
        print(k + ',', v)


# Setup expected arguments
parser = argparse.ArgumentParser(description='Azure waf log parser')
parser.add_argument('log_files', help='Path to waf log files')
args = parser.parse_args()

# Data structures
_results = {}
_descriptions = {}
_client_ips = {}

# Find log files
found_files = find_log_files(args.log_files, r'.*.json')

# Parse and report
for file in found_files:
    parse_log_file(_results, _descriptions, _client_ips, file)

report_triggered_rules(_results, _descriptions)
report_client_ips(_client_ips)