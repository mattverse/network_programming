import dns.query
import dns.message
import time
from datetime import datetime

# root servers defined from iana.org
ROOT_SERVERS = [
    '198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13',
    '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
    '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
    '202.12.27.33'
]

def query_ns(domain, ns_address):
    """Query specific nameserver for the given domain"""
    # use dns_python library to make single query for the given domain.
    try:
        query = dns.message.make_query(domain, dns.rdatatype.A)
        response = dns.query.udp(query, ns_address, timeout=10)
        return response
    except (dns.query.BadResponse, dns.query.Timeout, Exception) as e:
        print(f"Error querying {ns_address} for {domain}. Error: {str(e)}")
        return None

def get_next_domain(domain):
    """Break down the given domain into previous sub-domain. Example: 'www.cnn.com' -> 'cnn.com'."""
    parts = domain.split('.')
    # If length of parts is less then 2, it means that we are already at top level domain like google.com or it's a TLD
    if len(parts) <= 2:
        return None
    return '.'.join(parts[1:])

def iterative_query(domain):
    """Perform an iterative DNS query"""
    # Start iterative query starting from the root server
    ns_address = ROOT_SERVERS[0]
    attempt_count = 0 
    MAX_ATTEMPTS = 3 * len(ROOT_SERVERS)

    while attempt_count < MAX_ATTEMPTS:
        # QUery domain at the current name server address
        response = query_ns(domain, ns_address)
        if not response:
            attempt_count += 1
            ns_address = ROOT_SERVERS[attempt_count % len(ROOT_SERVERS)]
            continue
        if len(response.answer) > 0:
            a_record = None
            ttl_a = None

            for record in response.answer:
                if record.rdtype == dns.rdatatype.A:
                    a_record = record[0].address
                    ttl_a = record.ttl
                # If CNAME record is found, restart the algorithm using it as our new domain.
                elif record.rdtype == dns.rdatatype.CNAME:
                    domain = str(record[0].target)
                    continue  

            # if A record has been found, return it along with the TTL
            if a_record:
                return a_record, ttl_a

        ns_record = None
        # Handle Authority section of the response if not found from steps above.
        if len(response.authority) > 0:
            for record in response.authority:
                # Extract NS Record
                if record.rdtype == dns.rdatatype.NS:
                    ns_record = str(record[0].target)
                    break

        # If we have a new nameserver from the authority section,
        if ns_record:
            # Try getting the IP Address of the found name server
            ns_address = None
            for record in response.additional:
                if record.rdtype == dns.rdatatype.A:
                    ns_address = record[0].address
                    break

            # If failed to find IP address, restart algorithm and use NS domain + root server
            if not ns_address:
                domain = ns_record
                ns_address = ROOT_SERVERS[0]
                continue
        else:
            # if no name server has been found, get next domain and query parent domain
            next_domain = get_next_domain(domain)
            if next_domain:
                domain = next_domain
                ns_address = ROOT_SERVERS[0]
                continue
            # Dead end: exit program
            return None, None 

def mydig(domain):
    start_time = time.time()
    ip, ttl_a = iterative_query(domain)
    end_time = time.time()
    duration = round((end_time - start_time) * 1000)

    print("QUESTION SECTION:", domain, "IN A")
    if not ip:
        print("ERROR: Failed to resolve domain.")
        return
    if ip:
        print("ANSWER SECTION:")
        print(f"{domain}. {ttl_a} IN A {ip}")
    print(f"Query time: {duration}ms")
    print(f"WHEN: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == '__main__':
    domain = input("Enter the domain to resolve: ")
    mydig(domain)