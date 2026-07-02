import re
from datetime import datetime

# -------- TIME PARSER --------
def parse_time(timestr):
    """Convert HH:MM:SS to datetime object (same day baseline)"""
    return datetime.strptime(timestr, "%H:%M:%S")


# -------- LINE PARSER --------
def parse_office_line(line):
    """
    Extract:
    - first time (display time)
    - second time (match time)
    - component
    """

    # Normalize HTML spacing
    line = line.replace("&nbsp;", " ")

    # Collapse excessive spaces but preserve double-space structure
    # (we'll split manually instead of full collapse)
    raw_parts = line.split("  ")  # split only on double spaces

    # Remove empty chunks
    raw_parts = [p.strip() for p in raw_parts if p.strip()]

    if len(raw_parts) < 5:
        return None

    try:
        # Example structure:
        # [T2GE 01:00:01, 03.03.25 01:00:00, PLANTERS, RANTLMNT, DEVTO PCD2, ...]

        first_block = raw_parts[0]
        second_block = raw_parts[1]

        # --- FIRST TIME ---
        first_time = first_block.split()[1]

        # --- SECOND TIME ---
        second_time = second_block.split()[1]

        # --- COMPONENT ---
        component = raw_parts[4]

        # ========================
        # SPECIAL INDICATION FORMATS
        # ========================

        # Example:
        # Door Alm Indicates Closed
        # -> Door Alm off

        if "Indicates" in component:
            parts = component.split()

            try:
                idx = parts.index("Indicates")

                device_name = " ".join(parts[:idx])

                if idx + 1 < len(parts):
                    state = parts[idx + 1].rstrip(".").lower()

                    if state == "closed":
                        component = f"{device_name} off"
                    elif state == "open":
                        component = f"{device_name} on"
                    else:
                        component = device_name

            except Exception:
                pass


        elif "Local Control Inds" in component:
            parts = component.split()

            try:
                idx = parts.index("Inds")

                device_name = " ".join(parts[:idx])

                if idx + 1 < len(parts):
                    state = parts[idx + 1].rstrip(".").lower()

                    if state == "off":
                        component = f"{device_name} off"
                    elif state == "on":
                        component = f"{device_name} on"
                    else:
                        component = device_name

            except Exception:
                pass

        # Example:
        # ... CO IND RESET
        # -> component off
        #
        # ... CO IND SET
        # -> component on

        elif "BACK TO TRAIN CO IND" or "CODED BLOCK IND IS" or "SWITCH NORMAL IND" or "SWITCH REVERSE IND" in line.upper():

            upper_line = line.upper()

            if " RESET" in upper_line:
                component = f"{component} off"
            elif " SET" in upper_line:
                component = f"{component} on"

        elif "SWITCH OVERLOAD" in line.upper():

            upper_line = line.upper()

            if " FAILED" in upper_line:
                component = f"{component} on"
            elif " RESTORED" in upper_line:
                component = f"{component} off"

        return {
            "display_time": first_time,
            "match_time": parse_time(second_time),
            "component": component,
            "full_line": line
        }

    except Exception:
        return None


# -------- FILE PARSER --------
def parse_office_file(filepath):
    """
    Returns list of parsed office entries
    """

    entries = []

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if "T2GE" not in line:
                continue

            parsed = parse_office_line(line)
            if parsed:
                entries.append(parsed)

    return entries


# -------- MATCHING --------
def match_office_to_packetswitch(office_entries, packetswitch_entries):
    """
    packetswitch_entries must contain:
    - time (datetime or HH:MM:SS string)
    - type ("Ind" or "Control")
    """
    
    results = []

    for ps in packetswitch_entries:

        
        if not ps.get("time"):
            results.append({"time_tag": "", "component": ""})
            continue

        # normalize packetswitch time


        if isinstance(ps["time"], str):
            if not ps["time"].strip():
                results.append({"time_tag": "", "component": ""})
                continue

            ps_time = parse_time(ps["time"].split(".")[0])
        else:
            ps_time = ps["time"]
            ps_time = datetime.strptime(ps_time.strftime("%H:%M:%S"), "%H:%M:%S")

        ps_type = ps.get("type", "")


        if ps_type == "Ind":
            indicator_match = True
        elif ps_type == "Control":
            keyword = "Signal Request"
        else:
            continue



        matched_components = []
        matched_time = ""


 
        for office in office_entries:
            
            if not office.get("match_time"):
                continue

            time_diff = abs((office["match_time"] - ps_time).total_seconds())

            if time_diff <= 1:
                if ps_type == "Ind":
                    if (
                        "Track Indicates" in office["full_line"]
                        or "Indicates" in office["component"]
                        or "Local Control Inds" in office["component"]
                        or "CODED BLOCK IND IS" in office["full_line"].upper()
                        or "BACK TO TRAIN CO IND" in office["full_line"].upper()
                        or "SWITCH NORMAL IND" in office["full_line"].upper()
                        or "SWITCH REVERSE IND" in office["full_line"].upper()
                        or "SWITCH OVERLOAD" in office["full_line"].upper()
                    ):
                        matched_components.append(office["component"])

                        if not matched_time:
                            matched_time = office["display_time"]



                elif ps_type == "Control":
                    if "Signal Request" in office["full_line"]:
                        matched_components.append(office["component"])

                        if not matched_time:
                            matched_time = office["display_time"]



        # build result row
        results.append({
            "time_tag": matched_time,
            "component": " / ".join(matched_components)
        })


    return results
