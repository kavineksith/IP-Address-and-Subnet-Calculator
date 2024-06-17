import csv
import ipaddress
import json
import os
from pathlib import Path
import sys


class IPAddressConverter:
    def __init__(self, ip):
        self.ip = ip

    def to_decimal_and_hex(self):
        try:
            decimal_ip = int(ipaddress.ip_address(self.ip))
            hex_ip = hex(decimal_ip)
            return decimal_ip, hex_ip
        except ValueError:
            raise ValueError("Invalid IP address format")

    def to_binary(self):
        try:
            binary_ip = format(int(ipaddress.ip_address(self.ip)), '032b')
            return binary_ip
        except ValueError:
            raise ValueError("Invalid IP address format")


class SubnetCalculator:
    def __init__(self, ip, cidr):
        self.ip = ip
        self.cidr = cidr

    def calculate_subnet(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.network_address, network.netmask
        except ValueError as ve:
            print(f"Error in calculate_subnet: {ve}")
            raise ValueError("Invalid IP address or CIDR notation")

    def subnet_mask_binary(self):
        try:
            subnet_mask = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).netmask
            return bin(int(subnet_mask))
        except ValueError as ve:
            print(f"Error in subnet_mask_binary: {ve}")
            raise ValueError("Invalid IP address or CIDR notation")

    def host_mask_calculator(self):
        try:
            host_mask = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).hostmask
            return host_mask
        except ValueError as ve:
            print(f"Error in host_mask_calculator: {ve}")
            raise ValueError("Invalid IP address or CIDR notation")

    def host_mask_binary(self):
        try:
            host_mask = self.host_mask_calculator()
            # Determine IP version
            ip_version = ipaddress.ip_address(self.ip).version
            if ip_version == 4:
                # For IPv4, use 32 bits
                return "{0:032b}".format(int(host_mask))
            else:
                raise ValueError("Invalid IP version")
        except ValueError as ve:
            print(f"Error in host_mask_binary: {ve}")
            raise ValueError("Invalid IP address or CIDR notation")

    def subnet_binary(self):
        try:
            subnet = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).network_address
            return format(int(subnet), '032b')
        except ValueError as ve:
            print(f"Error in subnet_binary: {ve}")
            raise ValueError("Invalid IP address or CIDR notation")

    def usable_host_ip_range(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            usable_hosts = list(network.hosts())
            first_host, last_host = usable_hosts[0], usable_hosts[-1]
            ip_range_converter = IPAddressConverter(str(first_host)), IPAddressConverter(str(last_host))
            ip_range_str = f"{ip_range_converter[0].to_decimal_and_hex()[0]} - {ip_range_converter[1].to_decimal_and_hex()[0]}"
            return ip_range_str
        except ValueError as ve:
            print(f"Error in usable_host_ip_range: {ve}")
            raise ValueError("Invalid IP address or CIDR notation")

    def broadcast_address(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.broadcast_address
        except ValueError as ve:
            print(f"Error in broadcast_address: {ve}")
            raise ValueError("Invalid IP address or CIDR notation")

    def total_number_of_hosts(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.num_addresses
        except ValueError as ve:
            print(f"Error in total_number_of_hosts: {ve}")
            raise ValueError("Invalid IP address or CIDR notation")

    def number_of_usable_hosts(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            check_host_count = network.num_addresses - 2
            if check_host_count <= 0:
                return '0'
            else:
                return check_host_count
        except ValueError as ve:
            print(f"Error in number_of_usable_hosts: {ve}")
            raise ValueError("Invalid IP address or CIDR notation")

    def network_address(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.network_address
        except ValueError as ve:
            print(f"Error in network_address: {ve}")
            raise ValueError("Invalid IP address or CIDR notation")

    def cidr_notation(self):
        return self.cidr

    def ip_type(self):
        try:
            ip_obj = ipaddress.ip_address(self.ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                if ip_obj.is_private:
                    return "Private IPv4"
                elif ip_obj.is_loopback:
                    return "Loopback IPv4"
                elif ip_obj.is_link_local:
                    return "Link-local IPv4"
                elif ip_obj.is_reserved:
                    return "Reserved IPv4"
                elif ip_obj.is_unspecified:
                    return "APIPA (Automatic Private IP Addressing) IPv4"
                elif ip_obj.is_multicast:
                    return "Multicast IPv4"
                elif ip_obj.is_global:
                    return "Public IPv4"
            else:
                return "Other IPv4"
        except ValueError:
            raise ValueError("Invalid IP address")


def calculate_cidr_notation(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            # Count the number of bits set to 1 in the binary representation of the IPv4 address
            cidr = bin(int(ip_obj)).count("1")
            return cidr
    except ValueError:
        raise ValueError("Invalid IP address")


def validate_ip_address(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_ipv4_class(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            first_octet = int(ip.split('.')[0])
            if 1 <= first_octet <= 126:
                return 'A'
            elif 128 <= first_octet <= 191:
                return 'B'
            elif 192 <= first_octet <= 223:
                return 'C'
            elif first_octet == 127:
                return 'Loopback'
            elif first_octet == 0 or first_octet == 255:
                return 'Reserved'
            else:
                return 'Unknown'
    except ValueError:
        return None


def validate_input(ip_version, ip_address, cidr):
    try:
        if not ip_version or ip_version.lower() not in ['ipv4']:
            raise ValueError("Invalid IP version. Please enter 'IPv4' IP address.")

        if not ip_address:
            raise ValueError("Please enter a valid IP address.")

        if not validate_ip_address(ip_address):
            raise ValueError(f"Invalid {ip_version} address format.")

        cidr = int(cidr)  # convert cidr string to integer value

        if cidr < 0 or (ip_version == 'ipv4' and cidr > 32):
            raise ValueError("Invalid CIDR notation")

        return ip_address, cidr

    except ValueError as ve:
        print(f"Input validation error: {ve}")


def chunkstring(string, length):
    # IPv4 binary representation
    return (string[0 + i:length + i] for i in range(0, len(string), length))


def create_directory_and_generate_file_path(base_directory, file_name):
    """
    Creates a directory if it doesn't already exist and generates a file path.

    Args:
    - base_directory (str): Base directory path where the directory will be created and the file path will be generated.
    - file_name (str): Name of the file (including extension).

    Returns:
    - str: Full file path.
    """
    # Create directory if it doesn't exist
    directory_path = Path(base_directory)
    directory_path.mkdir(parents=True, exist_ok=True)

    # Generate file path
    file_path = directory_path / file_name

    return str(file_path)


def result_to_csv(labels, data, save_path):
    try:
        # Ensure both labels and data have the same length
        if len(labels) != len(data):
            raise ValueError("Lengths of labels and data do not match.")

        # Specify the filename where you want to save the JSON data
        filename = Path(save_path)

        if not os.path.exists(filename):
            # Open the file in write mode and immediately close it
            with open(filename, 'w'):
                pass

        # Check if the first line exists
        with open(filename, 'r') as check_file:
            first_line = check_file.readline().strip()
            # Open the file in append mode
            with open(filename, 'a', newline='') as csvfile:
                csvwriter = csv.writer(csvfile)

                # If the first line doesn't exist, write the header
                if not first_line:
                    csvwriter.writerow(labels)

                # Write data row
                csvwriter.writerow([str(item) for item in data])

        print("CSV data has been saved to", filename)
    except ValueError as ve:
        print(ve)
    except FileNotFoundError:
        print("Source file not found.")
        sys.exit(1)
    except PermissionError:
        print("Permission denied to access the source or export file.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("Process interrupted by the user.")
        sys.exit(1)
    except Exception as e:
        print("Error uploading data:", e)
        sys.exit(1)


def result_to_json(labels, data, save_path):
    try:
        # Ensure both labels and data have the same length
        if len(labels) != len(data):
            raise ValueError("Lengths of labels and data do not match.")

        # Create a dictionary pairing labels with data
        json_data = {label: value for label, value in zip(labels, data)}

        # Convert the dictionary to JSON string
        json_output = json.dumps(json_data, indent=4)

        # Specify the filename where you want to save the JSON data
        filename = Path(save_path)

        if not os.path.exists(filename):
            # Open the file in write mode and immediately close it
            with open(filename, 'w'):
                pass

        # Open the file in write mode and save the JSON data
        with open(filename, "a") as json_file:
            # json.dump(json_data, json_file, indent=4)
            json_file.write(json_output)

        print("JSON data has been saved to", filename)
    except ValueError as ve:
        print(ve)
    except FileNotFoundError:
        print("Source file not found.")
        sys.exit(1)
    except PermissionError:
        print("Permission denied to access the source or export file.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("Process interrupted by the user.")
        sys.exit(1)
    except Exception as e:
        print("Error uploading data:", e)
        sys.exit(1)


def result_to_display(labels, data):
    try:
        # Ensure both labels and data have the same length
        if len(labels) != len(data):
            raise ValueError("Lengths of labels and data do not match.")

        # Loop through each label and its corresponding data value
        for label, value in zip(labels, data):
            print(f"{label}: {value}")
    except ValueError as ve:
        print(ve)
    except KeyboardInterrupt:
        print("\nProcess interrupted by the user.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")


def data_process(usr_ip_address, output_selection=1, save_path=None):
    try:
        given_ip_address, given_cidr = usr_ip_address.strip().split('/')

        ip_address, cidr = validate_input("ipv4", given_ip_address, given_cidr)

        ip_class = validate_ipv4_class(ip_address)

        subnet_calculator = SubnetCalculator(ip_address, int(cidr))
        ip_converter = IPAddressConverter(ip_address)

        ip_type = subnet_calculator.ip_type()
        network_address = subnet_calculator.network_address()
        broadcast_address = subnet_calculator.broadcast_address()
        total_hosts = subnet_calculator.total_number_of_hosts()
        usable_hosts = subnet_calculator.number_of_usable_hosts()
        cidr_notation = subnet_calculator.cidr_notation()
        usable_host_range = subnet_calculator.usable_host_ip_range()

        decimal_ip, hex_ip = ip_converter.to_decimal_and_hex()
        binary_ip = ip_converter.to_binary()

        subnet, subnet_mask = subnet_calculator.calculate_subnet()
        host_mask = subnet_calculator.host_mask_calculator()
        subnet_mask_bin = subnet_calculator.subnet_mask_binary()
        subnet_bin = subnet_calculator.subnet_binary()
        host_mask_bin = subnet_calculator.host_mask_binary()

        labels = [
            "IPv4 address",
            "IPv4 class",
            "IPv4 Type",
            "Network Address",
            "Broadcast Address",
            "Total Number of Hosts",
            "Number of Usable Hosts",
            "CIDR Notation",
            "Usable Host IP Range",
            "Decimal representation",
            "Hexadecimal representation",
            "Binary representation",
            "Subnet",
            "Subnet mask",
            "Host mask",
            "Subnet binary",
            "Subnet mask binary",
            "Host mask binary"
        ]

        data = [
            str(ip_address),
            str(ip_class),
            str(ip_type),
            str(network_address),
            str(broadcast_address),
            str(total_hosts),
            str(usable_hosts),
            f'/{cidr_notation}',
            str(usable_host_range),
            str(decimal_ip),
            str(hex_ip),
            '.'.join(chunkstring(binary_ip[0:], 8)),
            f'{subnet}/{cidr}',
            str(subnet_mask),
            str(host_mask),
            '.'.join(chunkstring(subnet_bin[0:], 8)),
            '.'.join(chunkstring(subnet_mask_bin[2:], 8)),
            '.'.join(chunkstring(host_mask_bin, 8))
        ]

        if output_selection == 1:
            result_to_display(labels, data)
        elif output_selection == 2:
            result_to_csv(labels, data, save_path)
        elif output_selection == 3:
            result_to_json(labels, data, save_path)
        # else:
        #     print("Invalid selection. Please enter a number between 1 and 3.")

    except ValueError:
        print("Invalid input. Please enter a valid IPv4 address followed by CIDR notation (e.g., 192.168.1.1/24).")
    except KeyboardInterrupt:
        print("\nProcess interrupted by the user.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")


def main():
    while True:
        try:
            usr_ip_address = input("Enter IP address and CIDR notation (e.g., 192.168.1.1/24): ")
            if usr_ip_address.lower() == 'exit':
                print("Exiting the program.")
                sys.exit(0)
            elif usr_ip_address.lower() == "multiple":
                file_location = Path(input("Enter the file location: "))
                if not os.path.exists(file_location):
                    raise FileNotFoundError
                else:
                    try:
                        output_selection = int(input("Select a method (2 for CSV, 3 for JSON): "))
                        if output_selection in [2, 3]:
                            # User input for base directory and file name
                            base_directory = input("Enter base directory path: ").strip()
                            file_name = input("Enter file name (including extension): ").strip()

                            # Generate file path and create directory if necessary
                            file_path = create_directory_and_generate_file_path(base_directory, file_name)
                            print(f"Generated file path: {file_path}")
                        else:
                            print("Invalid selection. Please enter a number between 2 and 3.")
                            sys.exit(1)
                        with open(file_location, 'r', encoding='utf-8') as ip_list:
                            for item in ip_list:
                                data_process(item, output_selection, file_path)
                    except PermissionError:
                        print("Permission denied to access the source or export file.")
                        sys.exit(1)
            else:
                data_process(usr_ip_address, output_selection=1, save_path=None)
        except ValueError:
            print("Invalid input. Please enter a valid IPv4 address followed by CIDR notation (e.g., 192.168.1.1/24).")
        except FileNotFoundError:
            print("Source file not found.")
            sys.exit(1)
        except PermissionError:
            print("Permission denied to access the source or export file.")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\nProcess interrupted by the user.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
    sys.exit(0)
