# AssetX - Extract, Organize, Scan!

**AssetX** is a high-performance command-line tool written in Golang, designed for extracting and categorizing unique IPs, CIDR subnets, HTTP/HTTPS URLs, domains, and subdomains from a given file. It efficiently processes large files, making it ideal for cybersecurity professionals, penetration testers, and network analysts.

## Features
- Extracts **IPv4 addresses**, **CIDR subnets**, **http/https URLs**, **domains**, and **subdomains**.
- Expands **CIDR notations** to include all individual IPs in the range.
- Ensures URLs are correctly formatted with `http://` or `https://` before processing.
- Validates domains against the **IANA TLD list** (can be disabled with a flag).
- Automatically **splits data into multiple files** if the count exceeds a user-defined threshold.
- Provides a **structured JSON summary** of extracted assets.
- Optimized for speed and performance with parallel processing.

## Installation

### Prerequisites
- Ensure **Go** (Golang) is installed: [Download Go](https://go.dev/dl/)

### Install via `go install`
```sh
go install github.com/cyberxplore/assetx@latest
```
Run AssetX from anywhere:
```sh
assetx -f <input_file> -s <num>
```

### Build Manually
Alternatively, clone and build manually:
```sh
git clone https://github.com/cyberxplore/assetx.git
cd assetx
go build -o assetx assetx.go
```

## Usage
Run AssetX with an input file and optional parameters:
```sh
assetx -f <input_file> -s <num>
```
- `-f <input_file>`: File containing mixed data (IPs, URLs, domains, etc.).
- `-s <num>`: (Optional) If a category exceeds `<num>` items, it is split into smaller files. Default: `1000`.
- `-m <mode>`: Scan mode: `normal` (default) or `deep` (scans quoted literals only).
- `-k <bool>`: Enable/disable domain validation against IANA TLDs. Default: `true`.

### Example
Processing `sample.txt` with a split threshold of `500`:
```sh
assetx -f sample.txt -s 500
```

## Output Structure
- The tool creates an **output folder** named after the input file.
- Inside the folder:
  - A **root file** for each category (containing all extracted items).
  - **Split files** (if necessary) stored in subfolders.
  - A **JSON summary** printed to the terminal.

### Example JSON Output
```json
{
  "ips": {
    "count": 35,
    "isSplitted": false,
    "filenames": ["sample/sample_ips.txt"],
    "rootFile": "sample/sample_ips.txt"
  },
  "urls": {
    "count": 1500,
    "isSplitted": true,
    "filenames": [
      "sample/urls/sample_urls_1.txt",
      "sample/urls/sample_urls_2.txt"
    ],
    "rootFile": "sample/sample_urls.txt"
  },
  "domains": {
    "count": 1000,
    "isSplitted": true,
    "filenames": [
      "sample/domains/sample_domains_1.txt",
      "sample/domains/sample_domains_2.txt"
    ],
    "rootFile": "sample/sample_domains.txt"
  }
}
```

## Example Input (`sample.txt`)
```text
192.168.1.1 someRandomText 10.0.0.1 https://www.google.com
invalidToken 8.8.8.8 www.testsite.com/page example.com rubbish
foo bar 172.16.0.5 testsite.co.uk/page https://sub.example.com/somepath
127.0.0.1 randomWord subdomain.example.com
www.randomdomain.org something 10.10.10.10
http://secure.co.uk testdata https://blog.secure.co.uk
junk data http://192.168.0.5:8080/path more junk
192.168.2.0/29 sub.subdomain.example.com garbage-data
```

## Contributing
Contributions are welcome! Fork the repository and submit a pull request.

## License
MIT License

AssetX is developed by the [CyberXplore Team](https://cyberxplore.com).

