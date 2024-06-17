import csv
import ipaddress
import json
import os
from pathlib import Path
import sys


class IPAddressConverter:
    def __init__(self, ip):
        self.ip = ip

    def to_hex(self):
        try:
            decimal_ip = int(ipaddress.IPv6Address(self.ip))
            hex_ip = hex(decimal_ip)
            return hex_ip
        except ValueError:
            raise ValueError("Invalid IP address format")

    def to_binary(self):
        try:
            # Convert IPv6 address to packed bytes and then to hexadecimal representation
            binary_ip = ipaddress.IPv6Address(self.ip).exploded
            return binary_ip
        except ValueError:
            raise ValueError("Invalid IP address format")

    def to_decimal(self):
        try:
            decimal_ip = int(ipaddress.IPv6Address(self.ip))
            return decimal_ip
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
        except ValueError:
            raise ValueError("Invalid IP address or CIDR notation")

    def subnet_mask_binary(self):
        try:
            subnet_mask = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).netmask
            binary_subnet_mask = bin(int(subnet_mask))[2:]  # Remove '0b' prefix
            return binary_subnet_mask.zfill(128)  # Pad with zeros to ensure 128 bits
        except ValueError:
            raise ValueError("Invalid IP address or CIDR notation")

    def host_mask_calculator(self):
        try:
            host_mask = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).hostmask
            return host_mask
        except ValueError:
            raise ValueError("Invalid IP address or CIDR notation")

    def host_mask_binary(self):
        try:
            host_mask = self.host_mask_calculator()
            # For IPv6, use 128 bits
            return "{0:0128b}".format(int(host_mask))
        except ValueError:
            raise ValueError("Invalid IP address or CIDR notation")

    def subnet_binary(self):
        try:
            subnet = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False).network_address
            return format(int(subnet), '032b')
        except ValueError:
            raise ValueError("Invalid IP address or CIDR notation")

    def usable_host_ip_range(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            subnet = network.network_address
            broadcast = network.broadcast_address
            first_usable = subnet + 1
            last_usable = broadcast - 1
            return first_usable, last_usable
        except ValueError:
            raise ValueError("Invalid IP address or CIDR notation")

    def broadcast_address(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.broadcast_address
        except ValueError:
            raise ValueError("Invalid IP address or CIDR notation")

    def total_number_of_hosts(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.num_addresses
        except ValueError:
            raise ValueError("Invalid IP address or CIDR notation")

    def number_of_usable_hosts(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            check_host_count = network.num_addresses - 2
            if check_host_count <= 0:
                return 0
            else:
                return check_host_count
        except ValueError:
            raise ValueError("Invalid IP address or CIDR notation")

    def network_address(self):
        try:
            network = ipaddress.ip_network(self.ip + '/' + str(self.cidr), strict=False)
            return network.network_address
        except ValueError:
            raise ValueError("Invalid IP address or CIDR notation")

    def cidr_notation(self):
        return self.cidr

    def ip_type(self):
        try:
            ip_obj = ipaddress.ip_address(self.ip)
            if isinstance(ip_obj, ipaddress.IPv6Address):
                if ip_obj.is_private:
                    return "Private IPv6"
                elif ip_obj.is_loopback:
                    return "Loopback IPv6"
                elif ip_obj.is_link_local:
                    return "Link-local IPv6"
                elif ip_obj.is_site_local:
                    return 'Site-local IPv6'
                elif ip_obj.is_reserved:
                    return "Reserved IPv6"
                elif ip_obj.is_unspecified:
                    return "APIPA (Automatic Private IP Addressing) IPv6"
                elif ip_obj.is_global:
                    return "Public IPv6"
                elif ip_obj.ipv4_mapped:
                    return 'IPv4-Mapped IPv6'
                else:
                    # For other IPv6 addresses, check if it's multicast
                    if ip_obj.is_multicast:
                        return 'Multicast IPv6'
                    else:
                        return 'Global Unicast IPv6'
            else:
                return "Other IPv6"
        except ValueError:
            raise ValueError("Invalid IP address")


def chunkstring(string, length, delimiter=':'):
    if delimiter in string:
        # IPv6 binary representation with delimiters
        chunks = [string[i:i + length] for i in range(0, len(string), length)]
        return delimiter.join(chunks)
    else:
        # IPv6 binary representation without delimiters
        chunks = [string[i:i + length] for i in range(0, len(string), length)]
        return '.'.join(chunks)


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
        subnet_calculator = SubnetCalculator(given_ip_address, int(given_cidr))

        ip_type = subnet_calculator.ip_type()
        network_address = subnet_calculator.network_address()
        broadcast_address = subnet_calculator.broadcast_address()
        total_hosts = subnet_calculator.total_number_of_hosts()
        usable_hosts = subnet_calculator.number_of_usable_hosts()
        cidr_notation = subnet_calculator.cidr_notation()
        usable_host_range_start, usable_host_range_end = subnet_calculator.usable_host_ip_range()
        usable_host_range_str = f"{usable_host_range_start} - {usable_host_range_end}" if usable_host_range_start and usable_host_range_end else "N/A"

        ip_converter = IPAddressConverter(given_ip_address)
        binary_ip = ip_converter.to_binary()
        decimal_ip = ip_converter.to_decimal()
        hex_ip_raw = ip_converter.to_hex()
        hex_ip = ipaddress.IPv6Address(hex_ip_raw).exploded

        subnet_calculator = SubnetCalculator(given_ip_address, int(given_cidr))
        subnet, subnet_mask = subnet_calculator.calculate_subnet()
        subnet_mask_bin = subnet_calculator.subnet_mask_binary()
        subnet_bin = subnet_calculator.subnet_binary()
        host_mask = subnet_calculator.host_mask_calculator()
        host_mask_bin = subnet_calculator.host_mask_binary()

        # Convert subnet, subnet mask, and host mask to hexadecimal
        subnet_hex = subnet.exploded
        subnet_mask_hex = subnet_mask.exploded
        host_mask_hex = ipaddress.IPv6Address(int(host_mask_bin, 2)).exploded

        labels = [
            "IPv6 address",
            "IPv6 Type",
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
            "Host mask binary",
            "Subnet hexadecimal representation",
            "Subnet mask hexadecimal representation",
            "Host mask hexadecimal representation",
            "Subnet decimal representation",
            "Subnet mask decimal representation",
            "Host mask decimal representation"
        ]

        data = [
            str(given_ip_address),
            str(ip_type),
            str(network_address),
            str(broadcast_address),
            str(total_hosts),
            str(usable_hosts),
            f'/{cidr_notation}',
            str(usable_host_range_str),
            str(decimal_ip),
            str(hex_ip),
            str(binary_ip),
            f'{subnet}/{given_cidr}',
            str(subnet_mask),
            str(host_mask),
            str(chunkstring(subnet_bin, 8)),
            str(chunkstring(subnet_mask_bin, 8)),
            str(chunkstring(host_mask_bin, 8)),
            str(subnet_hex),
            str(subnet_mask_hex),
            str(host_mask_hex),
            str(int(subnet)),
            str(int(subnet_mask)),
            str(int(host_mask_bin, 2))
        ]

        if output_selection == 1:
            result_to_display(labels, data)
        elif output_selection == 2:
            result_to_csv(labels, data, save_path)
        elif output_selection == 3:
            result_to_json(labels, data, save_path)
        # else:
        #     print("Invalid selection. Please enter a number between 1 and 3.")

    except ValueError as ve:
        print(ve)
    except KeyboardInterrupt:
        print("\nProcess interrupted by the user.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")


def main():
    while True:
        try:
            usr_ip_address = input(
                "Enter IPv6 address and CIDR notation (e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334/64): ")
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
            print("Invalid input. Please enter a valid IPv6 address followed by CIDR notation (e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334/64).")
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
