# Subcollector

Subcollector is a tool designed for passive and active subdomain enumeration. It can be used to discover subdomains of a target domain using passive enumeration (using public APIs) or active enumeration (using brute-force with a wordlist).

## Features ✨

- **Passive Enumeration**: Uses public APIs to discover subdomains without sending direct requests to the target. 🌐
- **Active Enumeration**: Uses brute-force techniques with a wordlist to discover subdomains. 🔍
- **DNS Resolution**: Supports custom DNS resolvers for improved accuracy. 🎯
- **Rate Limiting**: Controls the speed of DNS requests to avoid detection or throttling. ⏳
- **Recursive Enumeration**: Allows recursive subdomain enumeration. 🔄
- **JSON Output**: Saves enumeration results in JSON format for further analysis. 📄


## Options

| Option                | Description                                                    |
|-----------------------|----------------------------------------------------------------|
| `-d`, `--domain`      | Target domain (e.g., example.com)                              |
| `-l`, `--list`        | Path to file containing list of domains                        |
| `-w`, `--wordlist`    | Path to custom wordlist file (optional)                        |
| `-r`, `--resolvers`   | Custom DNS resolvers (e.g., 8.8.8.8,1.1.1.1 or path to a file) |
| `-t`, `--rate-limit`  | Rate limit in milliseconds (default: 100)                      |
| `-R`, `-recursive`    | Enable recursive enumeration                                   |
| `-s`, `--show-ip`     | Show IP addresses for found subdomains                         |
| `-o`, `--output`      | Output results to file (text format)                           |
| `-j`, `--json-output` | Save results in JSON format (default: output.json)             |
| `-h`, `--help`        | Show help message                                              |
| `-v`, `--version`     | Display program version                                        |

## Example
1. Basic Passive Enumeration
   ```bash
   subcollector passive -d example.com
   ```
2. Basic Active Enumeration
   ```bash
   subcollector active -d example.com
   ```
3. Active Enumeration with Custom Wordlist and Resolver
   ```bash
   subcollector active -d example.com -w wordlist.txt -r resolvers.txt -t 200 -R -s
   ```
   
## Installation 🛠️

1. Ensure you have Go installed on your system. If not, you can download it from [here](https://golang.org/dl/).
2. Run the following command to install Subcollector:

   ```bash
   go install github.com/fkr00t/subcollector/cmd/subcollector@latest