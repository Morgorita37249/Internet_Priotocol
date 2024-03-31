import socket
import subprocess
import re
from ipwhois import IPWhois

class TracerouteAnalyzer:
    def __init__(self, target_domains: str | list[str], max_hops: int = 5):
        self.max_hops = max_hops
        self.target_domains = target_domains

    def trace_domain(self, target_domain: str | list[str], max_hops: int) -> list[str]:
        try:
            ip_address = socket.gethostbyname(target_domain)
            print(f"Tracing route to {target_domain} [{ip_address}]")
            tracert_output = subprocess.check_output(["tracert", "-h", str(max_hops), target_domain])
            return tracert_output
        except socket.gaierror:
            print("Hostname could not be resolved.")

    def get_as_info(self, ip_address: str) -> None:
        try:
            obj = IPWhois(ip_address)
            results = obj.lookup_rdap()
            as_number = results['asn']
            description = results['asn_description']
            print(f"AS number: {as_number}")
            print(f"AS description: {description}")
        except Exception as e:
            print(f"Error retrieving AS information for {ip_address}: {e}")

    def analyze_traces(self) -> None:
        if isinstance(self.target_domains, str):
            self.target_domains = [self.target_domains]

        for domain in self.target_domains:
            print('###################')
            print(domain)
            trace_info = self.trace_domain(domain, self.max_hops)

            if trace_info:
                trace_info = trace_info.decode('cp866')
                ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

                for trace_line in trace_info.split('\n'):
                    ipv4_matches = ipv4_pattern.findall(trace_line)
                    if ipv4_matches:
                        ip_address = ipv4_matches[0]
                        print(f"\nIP Address: {ip_address}")
                        self.get_as_info(ip_address)
            else:
                print('Trace list is empty.')


if __name__ == '__main__':
    TracerouteAnalyzer(target_domains=['lenta.ru', 'programforyou.ru', 'ekaterinburg.leroymerlin.ru'], max_hops=5).analyze_traces()