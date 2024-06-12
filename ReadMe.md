## Documentation: IP Address and Subnet Calculator 

### Introduction
The IP Subnet Calculator is a Python script designed to perform various calculations and analyses related to IPv4 and IPv6 addresses and subnets. It provides functionalities to convert IP addresses between different representations (decimal, hexadecimal, binary), calculate subnet details, determine IP address types, validate IP addresses, classify IPv4 addresses into classes, and more. Additionally, it offers the flexibility to output results in either terminal display, CSV files, or JSON format.

### Features
1. **IP Address Conversion:**
    - Convert IPv4 and IPv6 addresses to decimal, hexadecimal, and binary representations.
2. **Subnet Calculation:**
    - Calculate network address, broadcast address, total number of hosts, number of usable hosts, CIDR notation, usable host IP range, subnet, subnet mask, and host mask for a given IP address and CIDR notation.
3. **IP Address Type Identification:**
    - Determine the type of an IP address (e.g., private, public, loopback, link-local, multicast).
4. **Input Validation:**
    - Validate IP addresses and CIDR notations for correctness.
5. **IP Address Class Identification:**
    - Classify IPv4 addresses into classes (A, B, C, Loopback, Reserved, Unknown).
6. **Output Flexibility:**
    - Choose output format: terminal display, CSV files, or JSON format.
7. **User-Friendly Interface:**
    - Interactive command-line interface for easy interaction and usage.
8. **Error Handling:**
    - Robust error handling for various scenarios like invalid inputs, file not found, permission denied, etc.

### Installation
To begin using the IP Subnet Calculator, follow these straightforward steps:

1. **Clone the Repository**: Obtain the source code by cloning the GitHub repository:
   ```
   git clone https://github.com/kavineksith/IP-Address-and-Subnet-Calculator.git
   ```

2. **Navigate to the Project Directory**: Move into the cloned project directory:
   ```
   cd IP-Address-and-Subnet-Calculator
   ```

3. **Run the IP Subnet Calculator**: Execute the appropriate script (`ip_address_manager_v4.py` for IPv4 or `ip_address_manager_v6.py` for IPv6) to start using the IP Subnet Calculator:
   ```
   python ip_address_manager_v4.py
   ```

   ```
   python ip_address_manager_v6.py
   ```

By following these steps, you'll have the IP Subnet Calculator up and running in no time, ready to assist with your network management tasks.

### Usage
To use the IP Subnet Calculator, follow these steps:
1. **Run the Script:**
    - Execute the script (`ip_address_manager_v4.py` or `ip_address_manager_v6.py`).
2. **Input IP Address:**
    - Enter an IP address followed by CIDR notation (e.g., `192.168.1.1/24` for IPv4 or `2001:0db8:85a3:0000:0000:8a2e:0370:7334/64` for IPv6).
    - To exit the program, type `exit`.
    - To process multiple IP addresses from a file, type `multiple` and provide the file location.
3. **Select Output Format:**
    - Choose an output format:
        - `1`: Terminal Display
        - `2`: CSV File
        - `3`: JSON Format
4. **View Results:**
    - Results will be displayed according to the selected output format.

### Classes and Methods
#### `IPAddressConverter`
- **Methods:**
    - `to_decimal_and_hex`: Convert IP address to decimal and hexadecimal representations.
    - `to_binary`: Convert IP address to binary representation.

#### `SubnetCalculator`
- **Methods:**
    - `calculate_subnet`: Calculate network address and subnet mask.
    - `subnet_mask_binary`: Calculate subnet mask in binary.
    - `host_mask_calculator`: Calculate host mask.
    - `host_mask_binary`: Calculate host mask in binary.
    - `subnet_binary`: Calculate subnet in binary.
    - `usable_host_ip_range`: Calculate usable host IP range.
    - `broadcast_address`: Calculate broadcast address.
    - `total_number_of_hosts`: Calculate total number of hosts.
    - `number_of_usable_hosts`: Calculate number of usable hosts.
    - `network_address`: Get network address.
    - `cidr_notation`: Get CIDR notation.
    - `ip_type`: Determine IP address type.

#### Additional Functions
- `calculate_cidr_notation`: Calculate CIDR notation from an IP address.
- `validate_ip_address`: Validate IP address format.
- `validate_ipv4_class`: Classify IPv4 address into classes.
- `validate_input`: Validate user input.
- `chunkstring`: Split a string into chunks of specified length.
- `result_to_csv`: Write results to a CSV file.
- `result_to_json`: Write results to a JSON file.
- `result_to_display`: Display results in the terminal.
- `data_process`: Process user input and perform calculations.

### Dependencies
#### Standard Library Modules
- **`csv`**: Used for reading and writing CSV files.
- **`ipaddress`**: Provides classes and functions for working with IP addresses and networks.
- **`json`**: Used for encoding and decoding JSON data.
- **`os`**: Provides a portable way of using operating system-dependent functionality.
- **`pathlib.Path`**: Represents file system paths with semantics appropriate for different operating systems.
- **`sys`**: Provides access to some variables used or maintained by the Python interpreter and to functions that interact with the interpreter.

#### External Libraries
- **None**: Apart from the standard library modules, no external dependencies are required to run this script. All functionalities are implemented using built-in Python modules, ensuring portability and ease of use.

### Contributing
Contributions to the IP Address and Subnet Calculator are welcome! If you find any bugs or have suggestions for improvements, please submit an issue or open a pull request on GitHub.

### License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### Conclusion
The IP Subnet Calculator provides a versatile tool for network engineers, administrators, and enthusiasts to efficiently manage and analyze IP addresses and subnets. With its user-friendly interface, comprehensive functionalities, and robust error handling, it serves as a valuable asset in networking tasks and projects. The IP Subnet Calculator script is self-contained and does not rely on any third-party libraries beyond the Python standard library. This makes it easy to deploy and use across different environments without the need for additional installations or dependencies.

Please note that this project is intended for educational purposes only and should not be used for industrial applications. Any usage for commercial purposes falls outside the intended scope and responsibility of the creators, who explicitly disclaim liability or accountability for such usage.
