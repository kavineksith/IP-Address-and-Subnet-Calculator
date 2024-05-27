## Documentation: IP Address and Subnet Calculator 
### Overview
The IP Address and Subnet Calculator is a Python tool designed to facilitate calculations related to IP addresses and subnets. It offers various functionalities such as conversion of IP addresses to decimal, hexadecimal, and binary formats, calculation of subnet details including network address, broadcast address, total number of hosts, and more.

### Features
- **IP Address Conversion**: Convert IP addresses to decimal, hexadecimal, and binary formats.
- **Subnet Calculation**: Calculate subnet details including network address, broadcast address, total number of hosts, etc.
- **Input Validation**: Validate user inputs for IP addresses, CIDR notation, and IP version.
- **IPv4/IPv6 Class Identification**: Identify the class of IPv4 and IPv6 addresses.
- **User-Friendly Interface**: Interactive command-line interface for ease of use.

### Installation
To use the IP Address and Subnet Calculator, follow these steps:

1. Clone the repository from GitHub:
   ```
   git clone https://github.com/kavineksith/IP-Address-and-Subnet-Calculator.git
   ```

2. Navigate to the project directory:
   ```
   cd IP-Address-and-Subnet-Calculator
   ```

3. Run the main Python script:
   
   For IPv4 Versions:
   ```
   python ip_address_manager_v4.py
   ```
   For IPv6 Versions :
   ```
   python ip_address_manager_v6.py
   ```

### Usage
1. **Input Format**: Enter the IP address followed by the CIDR notation (e.g., `192.168.1.1/24`).
2. **Interactive Interface**: Follow the prompts to input the IP address and CIDR notation. Type `exit` to exit the program.
3. **Output**: View the calculated results including IP type, network address, broadcast address, total number of hosts, and more.

### Contributing
Contributions to the IP Address and Subnet Calculator are welcome! If you find any bugs or have suggestions for improvements, please submit an issue or open a pull request on GitHub.

### License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### Acknowledgements
The IP Address and Subnet Calculator utilizes the `ipaddress` module from the Python standard library for IP address manipulation and calculations. Special thanks to the Python community for providing valuable resources and support.

### Conclusion
Please note that this project is intended for educational purposes only and should not be used for industrial applications. Any usage for commercial purposes falls outside the intended scope and responsibility of the creators, who explicitly disclaim liability or accountability for such usage.