# Subcollector

Subcollector is a tool designed for passive and active subdomain enumeration. It can be used to discover subdomains of a target domain using passive enumeration (via public APIs) or active enumeration (via brute-force with a wordlist). Built with performance and usability in mind, Subcollector offers advanced features for security researchers and penetration testers.
## Features ✨

- **Passive Enumeration**: Uses public APIs to discover subdomains without sending direct requests to the target. 🌐
- **Active Enumeration**: Uses brute-force techniques with a wordlist to discover subdomains, optimized with worker pools and DNS caching. 🔍
- **Memory-Efficient Scanning**: Streaming technique for active scanning reduces memory usage with large wordlists. 💾
- **DNS Resolution**: Supports custom DNS resolvers for improved accuracy and flexibility. 🎯
- **Rate Limiting & Adaptive Backoff**: Controls request speed and adapts to server responses to avoid detection or throttling. ⏳
- **Recursive Enumeration**: Allows recursive subdomain enumeration with configurable depth. 🔄
- **Subdomain Takeover Detection**: Identifies subdomains vulnerable to takeover (AWS, Azure, GitHub Pages, and more). ⚠️
- **Anonymity**: Supports HTTP proxies for takeover detection requests to protect user privacy. 🕵️‍♂️
- **Real-time Results Display**: Shows results in real-time while maintaining progress tracking. 📊
- **Enhanced Progress Visualization**: Animated progress bars with ETA and scan statistics. 📈
- **Colored Output**: Uses color-coded console output to distinguish results and warnings. 🎨
- **Multiple Output Formats**: Save results in text or JSON format for further analysis. 📄
- **Optimized Performance**: Implements concurrent workers, batch processing, and DNS caching for faster enumeration. 🚀
- **Data Sanitization**: Ensures sensitive data is not inadvertently exposed in output. 🔒


# Options
## Passive Scans

| Flag | Long Flag | Type | Description |
|------|-----------|------|-------------|
| `-d` | `--domain` | string | Target domain (example: example.com) |
| `-h` | `--help` | | Help for passive |
| `-j` | `--json-output` | string | Save results in JSON format |
| `-l` | `--list` | string | Path to file containing list of domains |
| `-o` | `--output` | string | Save results to file (text format) |
| `-s` | `--show-ip` | | Show IP addresses for found subdomains |
| `-S` | `--stream` | | Stream results to output file (reduces memory usage) |
| `-v` | `--version` | | Display version information |                                                              |


## Active Scans
| Flag | Long Flag | Type | Description |
|------|-----------|------|-------------|
| `-D` | `--depth` | int | Recursion depth for active scanning (-1 for unlimited) (default 1) |
| `-d` | `--domain` | string | Target domain (example: example.com) |
| `-h` | `--help` | | Help for active |
| `-j` | `--json-output` | string | Save results in JSON format |
| `-l` | `--list` | string | Path to file containing list of domains |
| `-o` | `--output` | string | Save results to file (text format) |
| `-p` | `--proxy` | string | Proxy URL for HTTP requests (example: http://proxy:8090) |
| `-t` | `--rate-limit` | int | Rate limit in milliseconds (default 100) |
| `-R` | `--recursive` | | Enable recursive enumeration |
| `-r` | `--resolvers` | strings | Custom DNS resolvers (example: 8.8.8.8,1.1.1.1 or path to file) |
| `-s` | `--show-ip` | | Show IP addresses for found subdomains |
| `-S` | `--stream` | | Stream results to output file (reduces memory usage) |
| `-T` | `--takeover` | | Enable subdomain takeover detection |
| `-v` | `--version` | | Display version information |
| `-w` | `--wordlist` | string | Path to custom wordlist file |
| `-W` | `--workers` | int | Number of concurrent workers (default: 10) |
## Example
1. Basic Passive Enumeration
   ```bash
   subcollector passive -d example.com
   ```
2. Basic Active Enumeration
   ```bash
   subcollector active -d example.com
   ```
3. Active Enumeration with IP, Takeover Detection, and Proxy
   ```bash
   subcollector active -d example.com -s -T -p http://proxy:8080
   ```
4. Recursive Enumeration with Custom Wordlist and Output
   ```bash
   subcollector active -d example.com -w wordlist.txt -R -D 2 -o results.txt
   ```
   
## Installation 🛠️

1. Ensure you have Go installed on your system. If not, you can download it from [here](https://golang.org/dl/).
2. Install Subcollector and its dependencies:
   ```bash
   go install github.com/fkr00t/subcollector/cmd/subcollector@latest
   ```
   or, you can use this
   ```bash
   go install github.com/fkr00t/subcollector/cmd/subcollector@v1.4.2
   ```


## Contributing
Feel free to submit issues or pull requests to the GitHub repository. Contributions to improve performance, add new takeover patterns, or implement API support are welcome!