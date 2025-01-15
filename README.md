# Substorm 

Substorm is a tool designed for passive and active subdomain enumeration. It can be used to discover subdomains of a target domain using passive enumeration (using public APIs) or active enumeration (using brute-force with a wordlist).

## Features ✨

- **Passive Enumeration**: Uses public APIs to discover subdomains without sending direct requests to the target. 🌐
- **Active Enumeration**: Uses brute-force techniques with a wordlist to discover subdomains. 🔍
- **DNS Resolution**: Supports custom DNS resolvers for improved accuracy. 🎯
- **Rate Limiting**: Controls the speed of DNS requests to avoid detection or throttling. ⏳
- **Recursive Enumeration**: Allows recursive subdomain enumeration. 🔄
- **JSON Output**: Saves enumeration results in JSON format for further analysis. 📄


## Options

| Option              | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `-d`                | Target domain (e.g., example.com)                                           |
| `-active`           | Enable active enumeration                                                  |
| `-w`                | Path to custom wordlist file (optional)                                     |
| `-r`                | Path to custom DNS resolvers file                                           |
| `-rl`               | Rate limit in milliseconds (default: 100)                                   |
| `-recursive`        | Enable recursive enumeration                                               |
| `-oJ`               | Save results in JSON format (default: output.json)                          |
| `-o`                | Save results to file                                                        |
| `-show-ip`          | Display IP addresses for found subdomains                                   |
| `-version`          | Display program version                                                     |

## Installation 🛠️

1. Ensure you have Go installed on your system. If not, you can download it from [here](https://golang.org/dl/).
2. Run the following command to install Substorm:

   ```bash
   go install github.com/fkr00t/substorm@latest