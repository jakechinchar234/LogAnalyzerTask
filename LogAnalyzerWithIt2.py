#=====================================================
# LogAnalyzerWithIt2.py
# Jake Chinchar
# Purpose: Analyze Communication Manager logs, Wireshark PCAP files, and Packetswitch HTML reports to correlate message flows.
# Output: Generates a formatted Excel report summarizing findings
# Date last edited: 11/12/2025
#=====================================================

# Filters for WS
# current filter: ((atcsl3.srce_addr contains 71:a3:a7:8a:36) || (atcsl3.dest_addr contains 71:a3:a7:8a:36)) && !(_ws.col.protocol == "ATCS/TCP")
# current filter: ((atcsl3.srce_addr contains 71:a3:a7:8a:33) || (atcsl3.dest_addr contains 71:a3:a7:8a:33)) && !(_ws.col.protocol == "ATCS/TCP")

# Git commands for terminal
# git status
# git add LogAnalyzerWithIt2.py
# git commit -m "Describe what was changed"
# git push origin main

# Required packages:
# pip install scapy pandas openpyxl beautifulsoup4

# Import necessary libraries
import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import rdpcap, Raw
from scapy.layers.inet import TCP
from datetime import datetime, timedelta
import re
import os
import pandas as pd
from openpyxl import load_workbook
from openpyxl.styles import Alignment
from openpyxl.utils import get_column_letter
from bs4 import BeautifulSoup

# Expression to extract time tags from log lines (e.g., 12:34:56.78)
time_pattern = re.compile(r'\b\d{2}:\d{2}:\d{2}\.\d{2}\b')

# Converts a time string to a datetime object
def parse_time_only(ts_str):
    # Hours:Minutes:Seconds.Decimal
    return datetime.strptime(ts_str, '%H:%M:%S.%f')

# Formats a timedelta object into a readable string (HH:MM:SS.ms)
def format_timedelta(td):
    total_seconds = int(td.total_seconds())
    milliseconds = int(td.microseconds / 10000)
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{hours:02}:{minutes:02}:{seconds:02}.{milliseconds:02}"

# Checks if a packet contains the target address and is not TCP
# In the future, TCP will be ok to look at
def is_valid_packet(pkt, data_bytes, target_address):
    return target_address in data_bytes and not TCP in pkt

# Searches for a matching packet in the pcap file
def find_pcap_time(search_bytes, log_dt, packets, target_address):
    for pkt in packets:
        if Raw in pkt and target_address in pkt[Raw].load:
            data_bytes = pkt[Raw].load
            if search_bytes in data_bytes and target_address in data_bytes and not TCP in pkt:
                pcap_time = float(pkt.time)
                pcap_dt = datetime.fromtimestamp(pcap_time)
                pcap_ts_str = pcap_dt.strftime('%H:%M:%S.%f')[:-3]

                try:
                    pcap_time_only = datetime.strptime(pcap_ts_str, '%H:%M:%S.%f')
                    
                    time_diff = pcap_time_only - log_dt
                    minutes_diff = time_diff.total_seconds() / 60
                    # Valid minutes difference allowed (wireshark time tag can be -8 minutes before or 8 minutes
                    
                    # Additional filter
                    if pcap_time_only < (log_dt - timedelta(minutes=8)):
                        continue

                    # Valid time range of messages (comms manager time tags are not accurate and this may need to be changed)
                    if -8 <= minutes_diff <= 8:
                        formatted_data = extract_ws_hex_data(data_bytes)
                        return pcap_ts_str, format_timedelta(time_diff), True, formatted_data
                    else:
                        # The wireshark message found does not correspond to the communication manager message with the same msg number and type
                        # Messages with "Found but overflow" are not going to be printed ti the excel file
                            return pcap_ts_str, "Found but overflow", False, ''
                except:
                    continue

    # if no messages or overflow were found
    return None, "LOST", False, ''
        

# Checks if the output Excel file is currently open/locked
def is_file_open(filepath):
    try:
        os.rename(filepath, filepath)
        return False
    except:
        return True

def extract_ws_hex_data(data_bytes):
    full_hex_stream = data_bytes.hex()
    hex_data = ''
    if '0202128b' in full_hex_stream:
        idx = full_hex_stream.find('0202128b')
        data_start = idx + len('0202128b') + 8
        hex_data = full_hex_stream[data_start:data_start + 44]
    elif '02021201' in full_hex_stream:
        idx = full_hex_stream.find('02021201')
        data_start = idx + len('02021201') + 8
        hex_data = full_hex_stream[data_start:data_start + 22]
    formatted_data = ' '.join([hex_data[i:i+2] for i in range(0, len(hex_data), 2)]) if hex_data else ''
    return formatted_data



# MAIN FUNCTION that performs log analysis and writes results to Excel
def extract_hex_data(lines, start_index, msg_type_raw):
    hex_pairs = []
    i = start_index
    while i < len(lines) and len(hex_pairs) < 36:  # 4 to skip + 22 to collect
        line = lines[i]
        if 'BASIC' in line or 'INFO' in line:
            parts = line.strip().split()
            try:
                idx = parts.index('BASIC') if 'BASIC' in parts else parts.index('INFO')
                hex_candidates = parts[idx + 1:]
                for part in hex_candidates:
                    if part in ['TX', 'RX']:
                        break
                    if re.fullmatch(r'[0-9A-Fa-f]{2}', part):
                        hex_pairs.append(part)
            except ValueError:
                pass
        i += 1

    hex_pairs = hex_pairs[13:35]  # Skip first 4, take next 22

    if msg_type_raw == '12 8B':
        hex_pairs = hex_pairs[:22]
    elif msg_type_raw == '12 01':
        hex_pairs = hex_pairs[:11]
    else:
        hex_pairs = ''

    return ' '.join(hex_pairs)

def analyze_logs(log_file_path, pcap_file_path, start_time_str, end_time_str, packetswitch_file_path, target_address):

    # This is the filter applied
    target_address = target_address  # Target address to match in packets

    # Changes wanted for later
    # Add file to be rewritten
    # Allow user to name ending of ouput filename after log_packet_analysis
    output_file_path = 'log_packet_analysis_outputComp.xlsx'
    
    if os.path.exists(output_file_path) and is_file_open(output_file_path):
        messagebox.showerror("Error", "The output file is currently open. Please close it and try again.")
        return

    # Initialize storage for results and tracking
    cm_entries = []  # Communication Manager log entries
    ws_entries = []  # Wireshark log entries
    time_differences = []  # Time differences between logs
    last_two_sequences = []  # Last two hex sequences processed
    recent_sequence_times = {}  # Last timestamp for each hex sequence

    # As long as there is a communication manager log file given
    if log_file_path != False:
        
        # Parse start and end time inputs
        try:
            start_dt = parse_time_only(start_time_str)
            end_dt = parse_time_only(end_time_str)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid time format: {e}")
            return

        # Read log and pcap files
        with open(log_file_path, 'r') as log_file:
            lines = log_file.readlines()
        packets = rdpcap(pcap_file_path)

        # Read packetswitch files using Beautiful soup
        with open(packetswitch_file_path, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'html.parser')
            html_text = soup.get_text()

        # Process each line in the log file
        i = 0
        while i < len(lines):
            line = lines[i]
            time_match = time_pattern.search(line)
            if time_match:
                last_timestamp = time_match.group()
                try:
                    log_dt = parse_time_only(last_timestamp)
                except:
                    i += 1
                    continue
                # Only looks at entries between start and end time from user
                if not (start_dt <= log_dt <= end_dt):
                    i += 1
                    continue
            else:
                i += 1
                continue

            # Look for hex sequence pattern '02 02'
            if '02 02' in line:
                try:
                    index = line.index('02 02')
                    after = line[index + len('02 02'):].strip()
                    after_parts = after.split()
                    # This is in case the message number is '02'
                    if len(after_parts) >= 3 and after_parts[0] == '02':
                        msg_number = '02'
                        msg_type_raw = f"{after_parts[1]} {after_parts[2]}"
                    else:
                        # This is in all other cases a '02 02' message was found, but the message number is not '02'
                        pre_match = re.search(r'(\S{2})\s+02\s+02', line)
                        post_match = re.search(r'02\s+02\s+(\S{2})\s+(\S{2})', line)
                        msg_number = pre_match.group(1) if pre_match else None
                        msg_type_raw = f"{post_match.group(1)} {post_match.group(2)}" if post_match else None
                    msg_type = msg_type_raw
                    if msg_type_raw == '12 8B':
                        msg_type = 'Ind (12 8B)'
                    elif msg_type_raw == '12 01':
                        msg_type = 'Control (12 01)'
                    elif msg_type_raw == '12 48':
                        msg_type = 'Recall (12 48)'
                    
                    hex_sequence = f"{msg_number} 02 02 {msg_type_raw}" if msg_number and msg_type_raw else None
                except:
                    i += 1
                    continue

                # Skip if hex sequence is in last two entries read
                if not hex_sequence or hex_sequence in last_two_sequences:
                    i += 1
                    continue

                # Skip if hex sequence was seen in last 5 seconds
                if hex_sequence in recent_sequence_times:
                    if (log_dt - recent_sequence_times[hex_sequence]) <= timedelta(seconds=5):
                        i += 1
                        continue
                # Convert hex sequence to bytes
                try:
                    search_bytes = bytes.fromhex(hex_sequence)
                except:
                    i += 1
                    continue

                # Find matching pcap timestamp
                pcap_ts_str, time_diff_str, _, ws_hex_data = find_pcap_time(search_bytes, log_dt, packets, target_address)

                # Does not print entries found with overflow
                if time_diff_str != "Found but overflow":
                    # Store results
                    hex_data = extract_hex_data(lines, i, msg_type_raw)
                    cm_entries.append([last_timestamp, msg_type, msg_number, hex_data, ''])
                    ws_entries.append([pcap_ts_str or '', msg_type, msg_number, ws_hex_data, ''])
                    time_differences.append([time_diff_str])

                # Update tracking
                last_two_sequences.append(hex_sequence)
                if len(last_two_sequences) > 2:
                    last_two_sequences.pop(0)
                recent_sequence_times[hex_sequence] = log_dt

            i += 1


    # SECOND ITERATION: Scan Wireshark for 02 02 codes not found in CM log (also looks for RF_ACK now)
    # Only iteration if no communication manager log file is given
    last_rf_ack_time = None
    if log_file_path == False:
        # Initialized empty list for found communication manager log times (will remain empty)
        found_cm_times = set()
    else:
        found_cm_times = set(entry[0] for entry in cm_entries)
    additional_ws_entries = []
    additional_cm_entries = []
    additional_time_differences = []

    if log_file_path == False:
        packets = rdpcap(pcap_file_path)
        # Filter packets based on start time and end time from user given there is no comm manager file
        try:
            start_dt = parse_time_only(start_time_str)
            end_dt = parse_time_only(end_time_str)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid time format: {e}")
            return

        filtered_packets = []
        for pkt in packets:
            try:
                pkt_time = datetime.fromtimestamp(float(pkt.time))
                pkt_time_only = datetime.strptime(pkt_time.strftime('%H:%M:%S.%f')[:-3], '%H:%M:%S.%f')
                if start_dt <= pkt_time_only <= end_dt:
                    filtered_packets.append(pkt)
            except:
                continue
        packets = filtered_packets

        # Read packetswitch files
        with open(packetswitch_file_path, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'html.parser')
            html_text = soup.get_text()
        
    for pkt in packets:
        if Raw in pkt:
            data_bytes = pkt[Raw].load
            if is_valid_packet(pkt, data_bytes, target_address):
                hex_str = data_bytes.hex().upper()
                hex_parts = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
                for i in range(len(hex_parts) - 3):

                    # Additional logic to detect '8C' messages (RF_ACK)
                    for j in range(len(hex_parts) - 4):
                        if hex_parts[j] == '8C':
                            fourth_pair = hex_parts[j + 4]
                            if fourth_pair in ['34', '38']:
                                rf_ack_time = datetime.fromtimestamp(float(pkt.time))
                                if last_rf_ack_time and (rf_ack_time - last_rf_ack_time) <= timedelta(seconds=5):
                                    continue
                                msg_type = 'RF_ACK'
                                # Clarify between inbound and outbound
                                if fourth_pair in ['34']:
                                    msg_type = 'RF_ACK (Inbound)'
                                elif fourth_pair in ['38']:
                                    msg_type = 'RF_ACK (Outbound)'
                                last_rf_ack_time = rf_ack_time
                                pcap_time = datetime.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S.%f')[:-3]
                                additional_cm_entries.append(['Not found', '', '', '', ''])
                                additional_ws_entries.append([pcap_time, msg_type, '', '', ''])
                                additional_time_differences.append([''])
                                break
                        # Now look for '02 02'
                        if hex_parts[i] == '02' and hex_parts[i+1] == '02':

                            # Check if target address suffix is within 11 hex pairs before '02' (otherwise invalid 02 02)
                            suffix = target_address.hex()[-2:]
                            search_window = hex_parts[max(0, i-11):i]
                            if suffix not in search_window:
                                continue

                            # In case message number is 02  
                            if i > 0 and hex_parts[i+2] == '02':
                                msg_number = '02'
                                msg_type_raw = f"{hex_parts[i+3]} {hex_parts[i+4]}"
                            else:
                                msg_number = hex_parts[i-1] if i > 0 else None
                                msg_type_raw = f"{hex_parts[i+2]} {hex_parts[i+3]}"

                                msg_type = msg_type_raw
                            
                            if msg_type_raw == '04 D0':
                                continue

                            if msg_type_raw == '12 8B':
                                msg_type = 'Ind (12 8B)'
                            elif msg_type_raw == '12 01':
                                msg_type = 'Control (12 01)'
                            elif msg_type_raw == '12 48':
                                msg_type = 'Recall (12 48)'
                            hex_sequence = f"{msg_number} 02 02 {msg_type_raw}" if msg_number and msg_type_raw else None


                            if log_file_path != False:
                                # Skip if this hex sequence was already processed in the first iteration
                                if hex_sequence in [f"{entry[2]} 02 02 {entry[1].split('(')[-1].strip(')')}" for entry in cm_entries if entry[0] != 'Not found']:
                                    continue

                            pcap_time = datetime.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S.%f')[:-3]

                            # Skip if hex sequence is in last two entries
                            if not hex_sequence or hex_sequence in last_two_sequences:
                                continue

                            # Skip if hex sequence was seen in last 5 seconds
                            if hex_sequence in recent_sequence_times:
                                if (datetime.fromtimestamp(float(pkt.time)) - recent_sequence_times[hex_sequence]) <= timedelta(seconds=5):
                                    continue

                            # Update tracking
                            last_two_sequences.append(hex_sequence)
                            if len(last_two_sequences) > 2:
                                last_two_sequences.pop(0)
                            recent_sequence_times[hex_sequence] = datetime.fromtimestamp(float(pkt.time))

                            if pcap_time not in found_cm_times:
                                additional_cm_entries.append(['Not found', '', '', '', ''])
                                if log_file_path == False:
                                    ws_hex_data = extract_ws_hex_data(data_bytes)
                                    additional_ws_entries.append([pcap_time, msg_type, msg_number, ws_hex_data, ''])

                                else:
                                    ws_hex_data = extract_ws_hex_data(data_bytes)
                                    additional_ws_entries.append([pcap_time, msg_type, msg_number, ws_hex_data, ''])
                            
                                additional_time_differences.append([''])

    # Append new entries to original lists
    cm_entries.extend(additional_cm_entries)
    ws_entries.extend(additional_ws_entries)
    time_differences.extend(additional_time_differences)


    # Filter all entries based on user-defined start and end time
    filtered_entries = []
    for i, entry in enumerate(cm_entries):
        cm_time_str = entry[0]
        ws_time_str = ws_entries[i][0]

        try:
            # Parse timestamps
            cm_time = parse_time_only(cm_time_str) if cm_time_str != 'Not found' else None
            ws_time = parse_time_only(ws_time_str) if ws_time_str else None

            # Check if either timestamp is within range
            if (cm_time and start_dt <= cm_time <= end_dt) or (ws_time and start_dt <= ws_time <= end_dt):
                filtered_entries.append((entry, ws_entries[i], time_differences[i]))
        except:
            continue

    # Unpack filtered entries
    cm_entries = [e[0] for e in filtered_entries]
    ws_entries = [e[1] for e in filtered_entries]
    time_differences = [e[2] for e in filtered_entries]


    # Rebuild sorted entries based on CM time tag, placing 'Not found' entries before the next WS time
    # Step 1: Separate entries
    combined_entries = list(zip(cm_entries, ws_entries, time_differences))

    # Step 2: Sort entries with valid CM time tags
    valid_entries = [e for e in combined_entries if e[0][0] != 'Not found']
    valid_entries.sort(key=lambda x: parse_time_only(x[0][0]))

    # Step 3: Insert 'Not found' entries based on WS time tag
    did_not_find_entries = [e for e in combined_entries if e[0][0] == 'Not found']

    for entry in did_not_find_entries:
        ws_time_str = entry[1][0]
        try:
            ws_time = parse_time_only(ws_time_str)
        except:
            ws_time = datetime.max

        inserted = False
        for i, valid_entry in enumerate(valid_entries):
            try:
                next_ws_time = parse_time_only(valid_entry[1][0])
                if ws_time < next_ws_time:
                    valid_entries.insert(i, entry)
                    inserted = True
                    break
            except:
                continue
        if not inserted:
            valid_entries.append(entry)

    # Step 4: Unpack sorted entries
    cm_entries = [e[0] for e in valid_entries]
    ws_entries = [e[1] for e in valid_entries]
    time_differences = [e[2] for e in valid_entries]


    # Create dataframes for Excel Output
    cm_df = pd.DataFrame(cm_entries, columns=["time tag", "msg type (Hex)", "msg number (Hex)", "data (hex)", "direction"])
    ws_df = pd.DataFrame(ws_entries, columns=["time tag", "msg type (Hex)", "msg number (Hex)", "data (hex)", "UDP/TCP"])
    diff_df = pd.DataFrame(time_differences, columns=[" "])

    # Detect if packetswitch file contains 'Generic Report Results'
    is_generic_report = 'Generic Report Results' in html_text

    if not is_generic_report: # Not raw data packetswitch file
        
        # Packetswitch integration
        packetswitch_times, packetswitch_codes = [], []
        packetswitch_count = {}

        exit_bool = False
        for entry in ws_entries:
            msg_type_raw = entry[1].split('(')[-1].strip(')') if '(' in entry[1] else entry[1]
            if msg_type_raw not in ['12 8B', '12 01', '12 48']:
                packetswitch_times.append('')
                packetswitch_codes.append('')
                continue
            pcap_time = entry[0]
            msg_type = entry[1]
            code = ''

            if pcap_time:
                time_tag = pcap_time.split('.')[0]
                key = (time_tag, msg_type)
                count = packetswitch_count.get(key, 0)
                idx = -1

                for _ in range(count + 1):
                    idx = html_text.find(time_tag, idx + 1)
                    if idx == -1:
                        break

                if idx != -1:
                    after = html_text[idx:]
                    underscore_idx = after.find('_')
                    if underscore_idx != -1 and len(after) > underscore_idx + 2:
                        raw_code = after[underscore_idx + 1:underscore_idx + 3]
                        if raw_code == "CR" and msg_type == "Control (12 01)":
                            code = "Control"
                        elif raw_code == "IR" and msg_type == "Ind (12 8B)":
                            code = "Ind"
                        elif raw_code == "R_" and msg_type == "Recall (12 48)":
                            code = "Recall"

                if code:
                    packetswitch_times.append(time_tag)
                    packetswitch_codes.append(code)
                    packetswitch_count[key] = count + 1
                    exit_bool = True
                else:
                    exit_bool = False
            # Determine if the tenth digit of the pcap timestamp is '9'
            # Some entrie where the pcap timestamp is '9' have a matching entry in the next second
            tenth_digit_is_nine = False
            
            try:
                fractional = pcap_time.split('.')[-1]
                if len(fractional) >= 1 and fractional[0] == '9':
                    tenth_digit_is_nine = True
            except:
                pass


            # If no match found and tenth digit is 9, try again with +1 second
            if not code and tenth_digit_is_nine:
                adjusted_time = (datetime.strptime(time_tag, '%H:%M:%S') + timedelta(seconds=1)).strftime('%H:%M:%S')
                key = (adjusted_time, msg_type)
                count = packetswitch_count.get(key, 0)
                idx = -1
                for _ in range(count + 1):
                    idx = html_text.find(adjusted_time, idx + 1)
                    if idx == -1:
                        break
                if idx != -1:
                    after = html_text[idx:]
                    underscore_idx = after.find('_')
                    if underscore_idx != -1 and len(after) > underscore_idx + 2:
                        raw_code = after[underscore_idx + 1:underscore_idx + 3]
                        if raw_code == "CR" and msg_type == "Control (12 01)":
                            code = "Control"
                        elif raw_code == "IR" and msg_type == "Ind (12 8B)":
                            code = "Ind"
                        elif raw_code == "R_" and msg_type == "Recall (12 48)":
                            code = "Recall"
                exit_bool = False
                if code:
                    # packetswitch_times[-1] = adjusted_time
                    # packetswitch_codes[-1] = code
                    # packetswitch_count[key] = count + 1
                    # exit_bool = True
                    packetswitch_times.append(adjusted_time)
                    packetswitch_codes.append(code)
                    packetswitch_count[key] = count + 1
                    exit_bool = True
                    
            if exit_bool == False:
                packetswitch_times.append('')
                packetswitch_codes.append('')

    
    if is_generic_report: # Now if there is a raw data file
        packetswitch_times = []
        packetswitch_components = []  # Matched hex data
        packetswitch_codes = []       # Stores descriptive text

        # Parse packetswitch lines differently for Generic Report Results
        ps_lines = html_text.strip().split('\n')
        parsed_ps_lines = []
        for line in ps_lines:
            # Capture time, descriptive text, and hex data
            match = re.match(r".*?(\d{2}:\d{2}:\d{2})\s+([A-Za-z()]+)\s.*?:\s*([0-9A-Fa-f ]+)$", line)
            if match:
                time_tag = match.group(1)
                description = match.group(2)  # Text after time tag and before next number
                data = match.group(3).strip()
                parsed_ps_lines.append((time_tag, description, data))

        # For each Wireshark entry, check for matching data
        for ws_entry in ws_entries:
            ws_time_str = ws_entry[0].split('.')[0]  # Extract HH:MM:SS
            try:
                ws_time = datetime.strptime(ws_time_str, '%H:%M:%S')
            except:
                ws_time = None

            # Normalize Wireshark data: remove spaces, uppercase, and trim last two hex digits
            ws_data = ws_entry[3].replace(" ", "").upper()
            ws_data_trimmed = ws_data[:-2] if len(ws_data) > 2 else ws_data

            found_match = False
            for time_tag, description, ps_data in parsed_ps_lines:
                ps_data_clean = ps_data.replace(" ", "").upper()

                # Check if packetswitch data starts with Wireshark trimmed data
                if ps_data_clean.startswith(ws_data_trimmed):
                    try:
                        ps_time = datetime.strptime(time_tag, '%H:%M:%S')
                        time_diff = abs((ps_time - ws_time).total_seconds()) if ws_time else None
                    except:
                        time_diff = None

                    # Ensure time difference is within ±1 second
                    if time_diff is not None and time_diff <= 1:
                        if description == 'Indic(RF)' and ws_entry[1] != 'Ind (12 8B)':
                            continue
                        
                        if description == 'Rf' and ws_entry[1] != 'Control (12 01)':
                            continue  # Skip this packetswitch line

                        packetswitch_times.append(time_tag)
                        packetswitch_components.append(ps_data)# Store matched hex data
                        packetswitch_codes.append(description) # Store descriptive text
                        found_match = True
                        break

            # If no match found, append empty placeholders
            if not found_match:
                packetswitch_times.append('')
                packetswitch_components.append('')
                packetswitch_codes.append('')


    if is_generic_report:
        # Create dataframe for Packetswitch
        packetswitch_df = pd.DataFrame({
            "time tag": packetswitch_times,
            "component": packetswitch_components,  # New column for matched data
            "data type": packetswitch_codes
        })
    else:       
        # Create dataframe for Packetswitch
        packetswitch_df = pd.DataFrame({
            "time tag": packetswitch_times,
            "component": [''] * len(packetswitch_times),  # New column inserted here
            "data type": packetswitch_codes
        })

    # Combine all data into one dataframe with 'Number' column at the far left
    combined_df = pd.concat([
        pd.DataFrame({"Number": list(range(1, len(cm_df) + 1))}),  # New column added here
        cm_df, diff_df, ws_df, packetswitch_df
    ], axis=1)

    # Create header row for excel
    header_row = [
        " ",
        "Communication Manager Log", "", "", "", "",
        "Time Difference",
        "Wireshark Log", "", "", "", "",
        "Packetswitch Data", "", ""
    ]

    # Write to excel file
    with pd.ExcelWriter(output_file_path, engine="openpyxl") as writer:
        pd.DataFrame([header_row]).to_excel(writer, index=False, header=False)
        combined_df.to_excel(writer, index=False, startrow=1)

    # Format Excel file: merge headers and center align
    wb = load_workbook(output_file_path)
    ws = wb.active

    # Freeze top two rows
    ws.freeze_panes = "A3"
    
    # Merge headers
    ws.merge_cells(start_row=1, start_column=2, end_row=1, end_column=6)  # CM Log
    ws.merge_cells(start_row=1, start_column=7, end_row=1, end_column=7)  # Time Diff
    ws.merge_cells(start_row=1, start_column=8, end_row=1, end_column=12) # Wireshark
    ws.merge_cells(start_row=1, start_column=13, end_row=1, end_column=15) # Packetswitch

    # Center Align
    for col in [2, 7, 8, 13]:
        cell = ws.cell(row=1, column=col)
        cell.alignment = Alignment(horizontal='center', vertical='center')

    for row in ws.iter_rows(min_row=2, max_row=ws.max_row, min_col=1, max_col=15):
        for cell in row:
            cell.alignment = Alignment(horizontal='center', vertical='center')
    
    # Auto-adjust column widths
    for col in ws.iter_cols(min_row=2):
        max_length = 0
        column = col[0].column
        column_letter = get_column_letter(column)
        for cell in col:
            if cell.value:
                max_length = max(max_length, len(str(cell.value)))
        ws.column_dimensions[column_letter].width = max_length + 2

    wb.save(output_file_path)

    # Notify user of success
    messagebox.showinfo("Success", "Output has been saved to: log_packet_analysis_output.xlsx\nThe Excel file is ready to be viewed.")

# UI functions for file selection
def browse_log_file():
    filename = filedialog.askopenfilename(title="Select Communication Manager Log File", filetypes=[("Text Files", "*.txt")])
    log_file_entry.delete(0, tk.END)
    log_file_entry.insert(0, filename)

def browse_pcap_file():
    filename = filedialog.askopenfilename(title="Select Wireshark PCAP File", filetypes=[("PCAP Files", "*.pcap")])
    pcap_file_entry.delete(0, tk.END)
    pcap_file_entry.insert(0, filename)

def browse_packetswitch_file():
    filename = filedialog.askopenfilename(title="Select Packetswitch HTML File", filetypes=[("HTML Files", "*.html")])
    packetswitch_file_entry.delete(0, tk.END)
    packetswitch_file_entry.insert(0, filename)

# First function ran after the user selects run_analysis
def run_analysis():
    has_log = True
    log_file = log_file_entry.get()
    pcap_file = pcap_file_entry.get()
    packetswitch_file = packetswitch_file_entry.get()
    start_time = start_time_entry.get()
    end_time = end_time_entry.get()
    target_address_hex = target_address_entry.get().replace('0', 'a').replace('.', '')

    # Ensure user does not enter an odd number of hexadecimal digits
    import string
    def is_valid_hex(s):
        return len(s) % 2 == 0 and all(c in string.hexdigits for c in s)

    if not is_valid_hex(target_address_hex):
        messagebox.showerror("Error", "Target address must be even-length and contain only hex characters.")
        return


    if not os.path.isfile(pcap_file) or not os.path.isfile(packetswitch_file):
        messagebox.showerror("Error", "Please select valid file paths.")
        return

    if not log_file:
        has_log = False
        analyze_logs(has_log, pcap_file, start_time, end_time, packetswitch_file, bytes.fromhex(target_address_hex))   
    else: 
        analyze_logs(log_file, pcap_file, start_time, end_time, packetswitch_file, bytes.fromhex(target_address_hex))

# ********** Everything above this point is functions and libraries **********

# UI layout
root = tk.Tk()
root.title("Log Packet Analysis Tool")

tk.Label(root, text="Communication Manager Log Text File:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
log_file_entry = tk.Entry(root, width=60)
log_file_entry.grid(row=0, column=1, padx=10)
tk.Button(root, text="Browse", command=browse_log_file).grid(row=0, column=2, padx=10)

tk.Label(root, text="Wireshark PCAP File:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
pcap_file_entry = tk.Entry(root, width=60)
pcap_file_entry.grid(row=1, column=1, padx=10)
tk.Button(root, text="Browse", command=browse_pcap_file).grid(row=1, column=2, padx=10)

tk.Label(root, text="Packetswitch Data HTML File:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
packetswitch_file_entry = tk.Entry(root, width=60)
packetswitch_file_entry.grid(row=2, column=1, padx=10)
tk.Button(root, text="Browse", command=browse_packetswitch_file).grid(row=2, column=2, padx=10)

tk.Label(root, text="Start Time (HH:MM:SS.sss):").grid(row=3, column=0, sticky="w", padx=10, pady=5)
start_time_entry = tk.Entry(root, width=20)
start_time_entry.grid(row=3, column=1, sticky="w", padx=10)

tk.Label(root, text="End Time (HH:MM:SS.sss):").grid(row=4, column=0, sticky="w", padx=10, pady=5)
end_time_entry = tk.Entry(root, width=20)
end_time_entry.grid(row=4, column=1, sticky="w", padx=10)

tk.Label(root, text="Target Address:").grid(row=5, column=0, sticky="w", padx=10, pady=5)
target_address_entry = tk.Entry(root, width=20)
target_address_entry.grid(row=5, column=1, sticky="w", padx=10)

tk.Button(root, text="Run Analysis", command=run_analysis, bg="green", fg="white").grid(row=6, column=1, pady=20)
tk.Label(root, text="Enter the Target Address in any format", fg="purple").grid(row=7, column=0, columnspan=3, pady=10)

tk.Label(root, text="Output will be saved to: log_packet_analysis_output.xlsx\nYou will receive a message that the Excel file is ready to be viewed", fg="blue").grid(row=8, column=0, columnspan=3, pady=10)

# Start the UI event loop
root.mainloop()
