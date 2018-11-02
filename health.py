import argparse
import csv

import os
import re

from statsgen import StatsGen
from pprint import pprint
import csv

def generate_accounts_dict(john):
    """Generate a dictionary object containing user account information and weak passwords"""
    users = {}
    # Read in cracked password from John output and update user object in dictionary
    jlines = john.read().splitlines()
    for j in jlines:
        if ":" in j:
            if not j.split(":")[0].endswith("$"):  # Eliminate machine hashes
                # print "%s : %s" % (j.split(":")[0], j.split(":")[1])
                users[j.split(":")[0]] = j.split(":")[1]
    return users


def evaluate_password_health(users, print_password=False):
    """Evaluate the health of the passed in dictionary of accounts"""
    hasUpperCase = "[A-Z]"
    hasLowerCase = "[a-z]"
    hasNumbers = "\d"
    hasNonalphas = "\W"
    results = []
    for username, password in users.items():
        # print("testing: %s:%s" % (username, password))
        if print_password:
            printable_pass = password
        else:
            printable_pass = ""

        rules_dict = {"username":username,"password":printable_pass,"Length":1,"Capital":1,"Lower":1,"Digits":1,"Symbols":1}

        if len(password) < 8:
            print("Policy breach, too short : %s %s" % (username, printable_pass))
            rules_dict["Length"] = "0"

        elif len(password) > 8:
            # print("larger than 8")
            # raw_input('asdfasdf')
            breakRules = []
            score = 0;
            bestCase = 4
            # pprint(re.search(hasUpperCase, password))

            if not re.search(hasUpperCase, password):
                   breakRules.append("no upper case")
                   rules_dict["Capital"] = 0
            # print("upper")
            if not re.search(hasLowerCase, password):
                breakRules.append("no lower case")
                rules_dict["Lower"] = 0
            # print("lower")

            if not re.search(hasNumbers, password):
                breakRules.append("no numbers")
                rules_dict["Digits"] = 0

            # print("numbers")

            if not re.search(hasNonalphas, password):
                breakRules.append("non symbols")
                rules_dict["Symbols"] = 0

            # print("nonalphas")

            score = bestCase - len(breakRules)

            # print("%s score %s "%(password,score))  
            # raw_input('asdfasdf')
            if score <3:
                print("================\nPolicy breach: %s:%s %s " % (username, printable_pass, score ))

                for el in breakRules:
                    print("Broken Rule: %s"%el)

                print("================")
                results.append(rules_dict)
    return results
   
def generate_metrics(users):
    """Generate metrics from passed in dictionary of users"""

    # Generate Metrics
    uc = 0  # User Accounts
    mc = 0  # Machine Accounts
    metrics = {}  # metrics[<domain>][keys]; local and machine always exist

    for u in users:
        if users[u].get('type') == 'machine':
            d = 'machine'
        elif users[u].get('domain') is None:
            d = 'local'
        else:
            d = users[u].get('domain').lower()

        if d not in metrics.keys():  # Create "not" value by subtracting from total accounts
            metrics[d] = {'accounts': 0,
                          'crackedAccounts': 0,
                          'weakAccounts': 0,
                          'enabledAccounts': 0,
                          'lmHashes': [],
                          'ntlmHashes': [],
                          'blankLM': 0,
                          'blankNTLM': 0
                          }

        # Count accounts
        metrics[d]['accounts'] += 1

        # Count cracked accounts
        if users[u].get('cracked') is not None:
            metrics[d]['crackedAccounts'] += 1

        # Count weak accounts
        if users[u].get('weak') != "Not Cracked" and users[u].get('weak') != "Cracked":
            metrics[d]['weakAccounts'] += 1

        # Count enabled accounts
        if users[u].get('enabled') == 'Enabled':
            metrics[d]['enabledAccounts'] += 1

        # Add LM hashes
        if users[u].get('lm').lower() != "aad3b435b51404eeaad3b435b51404ee":
            metrics[d]['lmHashes'].append(users[u].get('lm').lower())
        elif users[u].get('lm').lower() == "aad3b435b51404eeaad3b435b51404ee":
            metrics[d]['blankLM'] += 1

        # Add NTLM hashes
        if users[u].get('ntlm').lower() != "31d6cfe0d16ae931b73c59d7e0c089c0":
            metrics[d]['ntlmHashes'].append(users[u].get('ntlm').lower())
        elif users[u].get('ntlm').lower() == "31d6cfe0d16ae931b73c59d7e0c089c0":
            metrics[d]['blankNTLM'] += 1

    print("Total Accounts:\t%s" % len(users))

    a = 0  # Accounts
    c = 0  # Cracked
    w = 0  # Weak
    e = 0  # Enabled
    lm = 0  # LM
    nt = 0  # NTLM
    bl = 0  # Blank LM
    bn = 0  # Blank NTLM
    ul = 0  # Unique LM
    un = 0  # Unique NTLM

    for m in metrics:
        a += metrics[m]['accounts']
        c += metrics[m]['crackedAccounts']
        w += metrics[m]['weakAccounts']
        e += metrics[m]['enabledAccounts']
        lm += len(metrics[m]['lmHashes'])
        nt += len(metrics[m]['ntlmHashes'])
        bl += metrics[m]['blankLM']
        bn += metrics[m]['blankNTLM']
        ul += len(set(metrics[m]['lmHashes']))
        un += len(set(metrics[m]['ntlmHashes']))
        if VERBOSE:
            print("%s" % m)
            print("\t" + "Accounts:\t\t\t%d" % metrics[m]['accounts'])
            print("\t" + "Cracked Accounts:\t\t%d" % metrics[m]['crackedAccounts'])
            print("\t" + "Uncracked Accounts:\t\t%d" % (metrics[m]['accounts'] - metrics[m]['crackedAccounts']))
            print("\t" + "Weak Accounts:\t\t%d" % metrics[m]['weakAccounts'])
            print("\t" + "Not Weak Accounts:\t\t%d" % (metrics[m]['accounts'] - metrics[m]['weakAccounts']))
            print("\t" + "Enabled Accounts:\t\t%d" % metrics[m]['enabledAccounts'])
            print("\t" + "Disabled Accounts:\t\t%d" % (metrics[m]['accounts'] - metrics[m]['enabledAccounts']))
            print("\t" + "Total LM Hashes:\t\t%d" % len(metrics[m]['lmHashes']))
            print("\t" + "Total NTLM Hashes:\t\t%d" % len(metrics[m]['ntlmHashes']))
            print("\t" + "Total Blank LM Hashes:\t%d" % metrics[m]['blankLM'])
            print("\t" + "Total Blank NTLM Hashes:\t%d" % metrics[m]['blankNTLM'])
            print("\t" + "Total Unique LM Hashes:\t%d" % len(set(metrics[m]['lmHashes'])))
            print("\t" + "Total Unique NTLM Hashes:\t%d" % len(set(metrics[m]['ntlmHashes'])))

    if args.output:
        with open(os.path.join(args.output, "ADPassHealth-Metrics.csv"), 'wb') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["", "Accounts", "LM", "NTLM", "Unique LM", "Unique NTLM", "Cracked",
                             "Blank LM", "Blank NTLM", "Weak", "Not Weak", "Enabled", "Disabled",
                             "Cracked (%)", "Enabled (%)"])
            for m in metrics:
                writer.writerow([m,
                                 metrics[m]['accounts'],
                                 len(metrics[m]['lmHashes']),
                                 len(metrics[m]['ntlmHashes']),
                                 len(set(metrics[m]['lmHashes'])),
                                 len(set(metrics[m]['ntlmHashes'])),
                                 metrics[m]['crackedAccounts'],  # TODO Update this to just account for LM
                                 metrics[m]['blankLM'],
                                 metrics[m]['blankNTLM'],
                                 metrics[m]['weakAccounts'],
                                 metrics[m]['accounts'] - metrics[m]['weakAccounts'],
                                 metrics[m]['enabledAccounts'],
                                 metrics[m]['accounts'] - metrics[m]['enabledAccounts'],
                                 "%.2f%%" % (float(metrics[m]['crackedAccounts']) / float(
                                     metrics[m]['accounts']) * 100),
                                 "%.2f%%" % (float(metrics[m]['enabledAccounts']) / float(
                                     metrics[m]['accounts']) * 100),
                                 ])

            writer.writerow(["Grand Total", a, lm, nt, ul, un, c, bl, bn, w, a - w, e, a - e,
                             "%.2f%%" % (float(c) / float(a) * 100), "%.2f%%" % (float(e) / float(a) * 100)])
            csv_file.close()

    if VERBOSE:
        print("Grand Total")
        print("\t" + "Accounts:\t\t\t%d" % a)
        print("\t" + "Cracked Accounts:\t\t%d" % c)
        print("\t" + "Uncracked Accounts:\t\t%d" % (a - c))
        print("\t" + "Weak Accounts:\t\t%d" % w)
        print("\t" + "Not Weak Accounts:\t\t%d" % (a - w))
        print("\t" + "Enabled Accounts:\t\t%d" % e)
        print("\t" + "Disabled Accounts:\t\t%d" % (a - e))
        print("\t" + "Total LM Hashes:\t\t%d" % lm)
        print("\t" + "Total NTLM Hashes:\t\t%d" % nt)
        print("\t" + "Total Blank LM Hashes:\t%d" % bl)
        print("\t" + "Total Blank NTLM Hashes:\t%d" % bn)
        print("\t" + "Total Unique LM Hashes:\t%d" % ul)
        print("\t" + "Total Unique NTLM Hashes:\t%d" % un)


if __name__ == '__main__':
    """Main function to run as script"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-J', '--john', type=argparse.FileType('r'), required=True,
                        help="A file with the output from John using the --show flag or hashes in this format "
                             "\033[0;0;92mACME.COM\\john:crackedPassword:RID:LMHash:NTLMHash::: (pwdLastSet) "
                             "(status)\033[0m. The pwdLastSet and status parts are optional.")
    parser.add_argument('-N', '--number', default=8, type=int,
                        help="Find all instances where the cracked password is less than the passed in number. Default "
                             "is \033[0;0;92m8\033[0m")
    parser.add_argument('-M', '--metrics', action='store_true', default=False,
                        help='Print metrics of AD password health data.')
    parser.add_argument('--machine', default=False, action='store_true',
                        help="Include machine accounts in results")
    parser.add_argument('-P', '--print_passwords', default=False, action='store_true',
                        help="Print passwords as part of output")
    # parser.add_argument('-O', '--output', help="Output directory", required=True)
    parser.add_argument('--verbose', action='store_true', default=False, help="Enable verbose Output")
    parser.add_argument('--debug', action='store_true', default=False, help="Enable debug output")
    parser.add_argument('--csv', default="pass_health.csv.learn_to_give_names_to_files", type=str, help="output to csv")

    args = parser.parse_args()

    DEBUG = args.debug
    VERBOSE = args.verbose
    accounts = generate_accounts_dict(args.john)
    breach_list = evaluate_password_health(accounts,print_password=args.print_passwords)
    stats = StatsGen()
    # for acc, password in accounts.items():
    #     stats.analyze_password(password=password)
    if args.metrics:
        stats.generate_stats(accounts)
        stats.print_stats()


    if args.csv is not None:
        fieldnames = ['username','password','Length','Capital','Lower','Digits','Symbols']
        with open(args.csv,'w') as csvfile:
            writer = csv.DictWriter(csvfile,fieldnames=fieldnames)
            writer.writeheader()
            for row in breach_list:
                writer.writerow(row)

    # pprint(accounts)
    # if args.aduserinfo:
    #     accounts = get_ad_user_info(accounts, args.aduserinfo)
    # write_password_health_csv(accounts, args.output)
    # if args.metrics:
    #     generate_metrics(accounts)
    # print "File saved to %s" % args.output
# TODO output metrics for the creation of pie charts
# TODO compare over time metrics
# TODO determine if account meets complexity requirements
