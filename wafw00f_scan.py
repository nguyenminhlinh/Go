import sys
from wafw00f.main import WAFW00F

def scan_waf(domain):
    # Khởi tạo đối tượng WAFW00F
    waf = WAFW00F(domain)

    # Chạy quét WAF
    waf_identified = waf.identwaf()

    if waf_identified:
        return f"WAF Detected: {waf_identified}"
    else:
        return "No WAF detected"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python wafw00f_scan.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    result = scan_waf(domain)

    # In kết quả
    print(result)
