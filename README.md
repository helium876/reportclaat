# ReportClaat

A powerful reconnaissance and reporting tool designed to automate the discovery and documentation of domain infrastructure. ReportClaat performs comprehensive domain analysis and generates professional reports with minimal user interaction.

## Features

- Subdomain enumeration using multiple sources
- Port scanning with service detection
- Automated screenshot capture of web services
- Parallel processing for faster execution
- Beautiful progress tracking and terminal output
- Comprehensive Word document report generation

## Requirements

- Python 3.8+
- Chrome/Chromium browser (for screenshots)
- nmap

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/helium876/reportclaat.git
cd reportclaat
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install Playwright browser:
```bash
python -m playwright install chromium
```

4. Install nmap:
```bash
# macOS
brew install nmap

# Linux
sudo apt install nmap

# Windows
# Download from https://nmap.org/download.html
```

5. Run the tool:
```bash
python reportclaat.py input.txt
```

## Usage

Basic usage:
```bash
python reportclaat.py input.txt
```

With options:
```bash
python reportclaat.py input.txt -o report.docx -t 16 --timeout 45 -q
```

### Command Line Options

- `input_file`: Input file containing domains/IPs (one per line)
- `-o, --output`: Output report filename (default: report.docx)
- `-q, --quiet`: Suppress non-essential output
- `-t, --threads`: Maximum number of concurrent threads
- `--timeout`: Timeout in seconds for network operations

### Input File Format

Create a text file with domains or IP addresses, one per line:
```text
example.com
subdomain.example.com
192.168.1.1
```

## Output

The tool generates a comprehensive Word document report containing:
- IP addresses
- Domain names
- Discovered services
- Open ports
- Website screenshots

## Author

- **Helium** - [GitHub](https://github.com/helium876)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and research purposes only. Users are responsible for complying with applicable laws and regulations. 