import re
from datetime import datetime

import os
from docx import Document

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
    raw_parts = line.split("  ")

    # Remove empty chunks
    raw_parts = [p.strip() for p in raw_parts if p.strip()]

    if len(raw_parts) < 5:
        return None

    try:
        first_block = raw_parts[0]
        second_block = raw_parts[1]

        # --- FIRST TIME ---
        first_time = first_block.split()[1]

        # --- SECOND TIME ---
        second_time = second_block.split()[1]

        # --- COMPONENT ---
        component = " ".join(raw_parts[4:])
        component = re.sub(r'^No\s+', '', component, flags=re.IGNORECASE)

        return {
            "display_time": first_time,
            "match_time": parse_time(second_time),
            "component": component,
            "full_line": line
        }

    except Exception:
        return None



def parse_office_file(filepath):
    """
    Returns list of parsed office entries
    Supports TXT, HTML and DOCX
    """

    entries = []

    ext = os.path.splitext(filepath)[1].lower()

    # TXT / HTML
    if ext in [".txt", ".html"]:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

    # DOCX
    elif ext == ".docx":
        doc = Document(filepath)
        lines = [p.text for p in doc.paragraphs]

    else:
        raise ValueError(f"Unsupported office file type: {ext}")

    for line in lines:
        if "T2GE" not in line:
            continue

        parsed = parse_office_line(line)

        if parsed:
            entries.append(parsed)

    print(f"Loaded {len(entries)} office entries from {filepath}")

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
        elif ps_type != "Recall":
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
                        or "SWITCH FLD LOCK IND" in office["full_line"].upper()
                        or "TIMING IND IS" in office["full_line"].upper()
                        or "CLEAR IND IS" in office["full_line"].upper()
                    ):
                        
                        component_text = office["component"]

                        # Skip switch indication state messages
                        if (
                            "Indicates Normal" in component_text
                            or "Indicates Reverse" in component_text
                            or "DK" in component_text
                        ):
                            continue


                        component_text = clean_component(office["component"])

                        matched_components.append(component_text)


                        if not matched_time:
                            matched_time = office["display_time"]



                elif ps_type == "Control":
                    if ("Signal Request" in office["full_line"]
                        or "NORMAL REQUEST IS" in office["full_line"].upper()
                        or "REVERSE REQUEST IS" in office["full_line"].upper()
                        or "RESEND CONTROLS CMD" in office["full_line"].upper()
                        ):
                        
                        component_text = clean_component(office["component"])

                        matched_components.append(component_text)


                        if not matched_time:
                            matched_time = office["display_time"]

                elif ps_type == "Recall":
                    if ("Remote Recall cmd" in office["full_line"]
                        or "REVERSE REQUEST IS" in office["full_line"].upper()                        
                        ):
                        component_text = clean_component(office["full_line"])

                        matched_components.append(component_text)

                        if not matched_time:
                            matched_time = office["display_time"]



        # build result row
        results.append({
            "time_tag": matched_time,
            "component": " / ".join(matched_components)
        })


    return results


def clean_component(component):
    """
    Remove trailing source identifiers such as:
    EVA rtc3
    DDM utB
    after the meaningful state word.
    """

    ending_patterns = [
        r"(.*?\bVacated\b).*",
        r"(.*?\bOccupied\b).*",
        r"(.*?\bReset\b).*",
        r"(.*?\bSet\b).*",
        r"(.*?\bOpen\b).*",
        r"(.*?\bClosed\b).*",
        r"(.*?\bOn\b).*",
        r"(.*?\bOff\b).*",
        r"(.*?\bRestored\b).*",
        r"(.*?\bFailed\b).*",
        r"(.*?\bClear\b).*",
        r"(.*?\bStop\b).*",
        r"(.*?\bapp\b).*",
        r"(.*?\bdisp\b).*",
        r"(.*?\bRecall cmd\b).*",
        
    ]

    for pattern in ending_patterns:
        m = re.match(pattern, component, flags=re.IGNORECASE)
        if m:
            return m.group(1)

    return component
