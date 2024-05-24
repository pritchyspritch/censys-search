import requests
import os


def censys_cert_search(domain):
    path = "search.censys.io/api/v2/certificates/search"
    q = f"names%3A%20{domain}%20"
    per_page = 100
    auth = os.getenv("censys_auth")
    another_page = True
    next_page = ""
    results_count = 0
    all_cert_info = []

    while another_page:
        headers = {
            "accept": "application/json",
            "Authorization": f"Basic {auth}"
        }
        print(headers)
        if next_page != "":
            certs = requests.get(f"https://{path}?q={q}&per_page={per_page}&cursor={next_page}", headers=headers)
        else:
            certs = requests.get(f"https://{path}?q={q}&per_page={per_page}", headers=headers)

        status = certs.status_code
        print(status)
        print(certs.text)
        results = certs.json()["result"]["hits"]

        results_count += len(results)

        for domain in results:
            subject_dn = domain["parsed"]["subject_dn"]
            issuer_dn = domain["parsed"]["issuer_dn"]
            names = domain["names"]

            only_specific_names = []
            for name in names:
                if name.endswith(domain):
                    only_specific_names.append(name)

            domain_dict = {
                "subject_dn": subject_dn,
                "issuer_dn": issuer_dn,
                "names": names,
                "only_specific_names": only_specific_names
            }

            all_cert_info.append(domain_dict)

            print(f"subject_dn: {subject_dn}\nissuer_dn: {issuer_dn}\nnames: {names}")

        print(certs.json()["result"]["links"])
        if certs.json()["result"]["links"]["next"] != "":
            next_page = certs.json()["result"]["links"]["next"]
            print(next_page)
            another_page = True
        else:
            another_page = False

        print(next_page)

    print(results_count)
    return all_cert_info

all_cert_info = censys_cert_search()
all_subjects = []
all_names = []
only_specific_names = []

for certs in all_cert_info:
    all_subjects.append(certs["subject_dn"].split("CN=")[1])
    all_names.append(certs["names"])
    only_specific_names.extend(certs["only_specific_names"])

specific_names_unique_list = list(dict.fromkeys(only_specific_names))
print(specific_names_unique_list)
print(len(specific_names_unique_list))
unique_subjects = list(dict.fromkeys(all_subjects))
print(unique_subjects)
