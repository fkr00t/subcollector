# Subcollector

Subcollector is a tool designed for passive and active subdomain enumeration. It can be used to discover subdomains of a target domain using passive enumeration (via public APIs) or active enumeration (via brute-force with a wordlist). Built with performance and usability in mind, Subcollector offers advanced features for security researchers and penetration testers.
## Features ✨

- **Passive Enumeration**: Uses public APIs to discover subdomains without sending direct requests to the target. 🌐
- **Active Enumeration**: Uses brute-force techniques with a wordlist to discover subdomains, optimized with worker pools and DNS caching. 🔍
- **DNS Resolution**: Supports custom DNS resolvers for improved accuracy and flexibility. 🎯
- **Rate Limiting**: Controls the speed of DNS requests to avoid detection or throttling. ⏳
- **Recursive Enumeration**: Allows recursive subdomain enumeration with configurable depth. 🔄
- **Subdomain Takeover Detection**: Identifies subdomains vulnerable to takeover (e.g., AWS, Azure, GitHub Pages). ⚠️
- **Anonymity**: Supports HTTP proxies for takeover detection requests to protect user privacy. 🕵️‍♂️
- **Progress Tracking**: Displays a progress bar during active enumeration for better user experience. 📊
- **Colored Output**: Uses color-coded console output to distinguish results and warnings. 🎨
- **JSON Output**: Saves enumeration results in JSON format for further analysis. 📄
- **Optimized Performance**: Implements batch DNS requests and caching for faster enumeration. 🚀
- **Data Sanitization**: Ensures sensitive data is not inadvertently exposed in output. 🔒
- **API Support**: (Planned) Future support for integration into automated workflows via an API. 🔗

## Options

| Option                | Description                                                                                |
|-----------------------|--------------------------------------------------------------------------------------------|
| `-d`, `--domain`      | Target domain (e.g., `example.com`)                                                        |
| `-l`, `--list`        | Path to file containing list of domains                                                    |
| `-w`, `--wordlist`    | Path to custom wordlist file (default: fetched from GitHub)                                |
| `-r`, `--resolvers`   | Custom DNS resolvers (e.g., `8.8.8.8,1.1.1.1` or path to file)                             |
| `-t`, `--rate-limit`  | Rate limit in milliseconds (default: 100)                                                  |
| `-E`,`--real-time`    | Display results in real-time while maintaining progress bar (default: true) (default true) |
| `-R`, `--recursive`   | Enable recursive enumeration                                                               |
| `-D`, `--depth`       | Recursion depth for active scanning (default: 1, `-1` for unlimited)                       |
| `-s`, `--show-ip`     | Show IP addresses for found subdomains                                                     |
| `-T`, `--takeover`    | Enable subdomain takeover detection                                                        |
| `-p`, `--proxy`       | Proxy URL for HTTP requests (e.g., `http://proxy:8080`)                                    |
| `-o`, `--output`      | Output results to file (text format)                                                       |
| `-j`, `--json-output` | Save results in JSON format (default: `output.json`)                                       |
| `-h`, `--help`        | Show help message                                                                          |
| `-v`, `--version`     | Display program version                                                                    |

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
   ```
   subcollector active -d example.com -w wordlist.txt -R -D 2 -o results.txt
   ```
   
## Installation 🛠️

1. Ensure you have Go installed on your system. If not, you can download it from [here](https://golang.org/dl/).
2. Install Subcollector and its dependencies:
   ```bash
   go install github.com/fkr00t/subcollector/cmd/subcollector@latest

## Contributing
Feel free to submit issues or pull requests to the GitHub repository. Contributions to improve performance, add new takeover patterns, or implement API support are welcome!