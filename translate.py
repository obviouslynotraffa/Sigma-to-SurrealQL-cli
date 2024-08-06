import subprocess
import os

with open("output.txt", "w") as f:
    f.write("")
    
with open("sqlite_queries.txt", "w") as f:
    f.write("")

with open("surreal_queries.txt", "w") as f:
    f.write("")

mapping = {
    "LIKE": "CONTAINS",
    "'%": "'",
    "%'": "'",  
    "EventID=3 AND ": "",
    "Initiated='true' AND ": "",
    " ESCAPE '\\'": "",
    "DestinationHostname" : "call",
    "\n": ";\n",
    "DestinationPort": "rport",
    "Image": "cmd"
}

tables = {
    "DestinationHostname": "dns_analizer",
    "Image": "net_comms"
}
    

folder = "./sigmatoconvert"

for file in os.listdir(folder):
    path = os.path.join(folder, file)
    converter_comand = "sigma convert -t sqlite -p sysmon " + path
    
    try:
        result = subprocess.run(converter_comand, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(e.stderr)

    sqlitext = result.stdout
    with open("sqlite_queries.txt", "a") as f:
        f.write(sqlitext)

    substitution_status = {key: False for key in mapping}

    # Convert to a SurrealSQL query fomat
    for key in mapping:
        if key in sqlitext:
            substitution_status[key] = True
            sqlitext = sqlitext.replace(key, mapping[key])
    
    # Replace table name
    for key, replaced in substitution_status.items():
        if replaced and key in tables:
            sqlitext = sqlitext.replace("<TABLE_NAME>", tables[key])

    with open("surreal_queries.txt", "a") as f:
        f.write(sqlitext)

    surreal_command = "surreal sql --endpoint http://localhost:8000 --user root --pass root --ns clavisi --db clavisidb --pretty"

    try:
        run_surrealsql = subprocess.Popen(surreal_command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        query_output = run_surrealsql.communicate(sqlitext)
    except subprocess.CalledProcessError as e:
        print(e.stderr)

    output = f"Sigma rule: {path}\n {query_output[0]} \n"
    
    with open("output.txt", "a") as f:
        f.write(output)
