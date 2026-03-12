import re
from collections import Counter, defaultdict
import heapq

class LogAnalyzer:
    def __init__(self):
        self.logs = []
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    def parse_log(self, log_line):
        ip_match = self.ip_pattern.search(log_line)
        ip = ip_match.group() if ip_match else None
        self.logs.append({"ip": ip, "line": log_line})
        return ip
    
    def parse_file(self, filepath):
        with open(filepath, 'r') as f:
            for line in f:
                self.parse_log(line.strip())
    
    def top_k_ips(self, k=10):
        ip_counter = Counter(log["ip"] for log in self.logs if log["ip"])
        return ip_counter.most_common(k)
    
    def detect_anomalies(self, threshold=100):
        ip_counter = Counter(log["ip"] for log in self.logs if log["ip"])
        anomalies = [(ip, count) for ip, count in ip_counter.items() if count > threshold]
        return sorted(anomalies, key=lambda x: x[1], reverse=True)
    
    def stream_process(self, log_line, window_size=1000):
        self.parse_log(log_line)
        if len(self.logs) > window_size:
            self.logs.pop(0)
        return self.top_k_ips(5)
    
    def search_pattern(self, pattern):
        regex = re.compile(pattern)
        return [log["line"] for log in self.logs if regex.search(log["line"])]

if __name__ == "__main__":
    print("\n=== LOG ANALYZER ===")
    analyzer = LogAnalyzer()
    
    while True:
        print("\n" + "="*40)
        print("1. Add Log Entry")
        print("2. View Top K IPs")
        print("3. Detect Anomalies")
        print("4. Search Pattern")
        print("5. View All Logs")
        print("6. Exit")
        choice = input("Enter choice: ")
        
        if choice == '1':
            log = input("Enter log entry: ")
            ip = analyzer.parse_log(log)
            print(f"✓ Parsed log (IP: {ip if ip else 'None'})")
        elif choice == '2':
            k = int(input("Enter K (top IPs): "))
            top_ips = analyzer.top_k_ips(k)
            if top_ips:
                print(f"\nTop {k} IPs:")
                for ip, count in top_ips:
                    print(f"  {ip}: {count} requests")
            else:
                print("No IPs found")
        elif choice == '3':
            threshold = int(input("Enter threshold: "))
            anomalies = analyzer.detect_anomalies(threshold)
            if anomalies:
                print("\nAnomalies detected:")
                for ip, count in anomalies:
                    print(f"  {ip}: {count} requests")
            else:
                print("No anomalies detected")
        elif choice == '4':
            pattern = input("Enter search pattern (regex): ")
            results = analyzer.search_pattern(pattern)
            if results:
                print(f"\nFound {len(results)} matches:")
                for log in results[:10]:
                    print(f"  {log}")
            else:
                print("No matches found")
        elif choice == '5':
            if analyzer.logs:
                print(f"\nTotal logs: {len(analyzer.logs)}")
                for log in analyzer.logs[:10]:
                    print(f"  {log['line']}")
                if len(analyzer.logs) > 10:
                    print(f"  ... and {len(analyzer.logs) - 10} more")
            else:
                print("No logs yet")
        elif choice == '6':
            break