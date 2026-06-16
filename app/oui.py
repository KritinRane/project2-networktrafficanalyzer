"""
OUI (Organizationally Unique Identifier) lookup.
Maps the first 3 octets of a MAC address to a manufacturer name.

The full OUI database is 5MB+. This module ships a curated subset of
the most common consumer/IoT vendors. For production, download the full
IEEE list: https://standards-oui.ieee.org/oui/oui.txt and parse it.
"""

OUI_TABLE: dict[str, str] = {
    # Apple
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "00:1E:52": "Apple",
    "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:24:36": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "00:50:E4": "Apple",
    "04:0C:CE": "Apple",
    "04:15:52": "Apple",
    "04:1E:64": "Apple",
    "04:26:65": "Apple",
    "04:52:F3": "Apple",
    "04:54:53": "Apple",
    "04:D3:CF": "Apple",
    "04:F7:E4": "Apple",
    "F0:9F:C2": "Apple",
    "F4:F1:5A": "Apple",
    "A4:C3:F0": "Apple",
    "AC:BC:32": "Apple",
    "B8:FF:61": "Apple",
    "C8:2A:14": "Apple",
    "DC:2B:2A": "Apple",
    "E0:B9:BA": "Apple",
    "F0:18:98": "Apple",
    # Samsung
    "00:12:47": "Samsung",
    "00:15:99": "Samsung",
    "00:17:C9": "Samsung",
    "00:1A:8A": "Samsung",
    "18:65:90": "Samsung",
    "20:64:32": "Samsung",
    "38:AA:3C": "Samsung",
    "40:0E:85": "Samsung",
    "50:01:BB": "Samsung",
    "5C:49:79": "Samsung",
    "70:F9:27": "Samsung",
    "8C:71:F8": "Samsung",
    "A0:0B:BA": "Samsung",
    "BC:47:60": "Samsung",
    "CC:07:AB": "Samsung",
    "E8:03:9A": "Samsung",
    "F4:42:8F": "Samsung",
    # Amazon
    "00:FC:8B": "Amazon",
    "34:D2:70": "Amazon",
    "40:B4:CD": "Amazon",
    "44:65:0D": "Amazon",
    "50:DC:E7": "Amazon",
    "68:37:E9": "Amazon",
    "74:75:48": "Amazon",
    "84:D6:D0": "Amazon",
    "A0:02:DC": "Amazon",
    "B4:7C:9C": "Amazon",
    "DC:A6:32": "Amazon",  # also Raspberry Pi
    "F0:27:2D": "Amazon",
    "FC:A1:83": "Amazon",
    # Google / Nest
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "54:60:09": "Google",
    "7C:2E:BD": "Google",
    "A4:77:33": "Google",
    "F4:F5:D8": "Google",
    "20:DF:B9": "Nest",
    "18:B4:30": "Nest",
    "64:16:66": "Nest",
    "74:DA:38": "Nest",
    # Raspberry Pi Foundation
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    # Netgear
    "00:09:5B": "Netgear",
    "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear",
    "00:18:4D": "Netgear",
    "00:1B:2F": "Netgear",
    "00:1E:2A": "Netgear",
    "00:22:3F": "Netgear",
    "00:24:B2": "Netgear",
    "00:26:F2": "Netgear",
    "20:4E:7F": "Netgear",
    "2C:30:33": "Netgear",
    "30:46:9A": "Netgear",
    "44:94:FC": "Netgear",
    "4F:44:D7": "Netgear",
    "6C:B0:CE": "Netgear",
    "A4:3E:51": "Netgear",
    "C0:3F:0E": "Netgear",
    # TP-Link
    "00:27:19": "TP-Link",
    "14:CC:20": "TP-Link",
    "18:D6:C7": "TP-Link",
    "1C:61:B4": "TP-Link",
    "2C:54:91": "TP-Link",
    "50:C7:BF": "TP-Link",
    "54:AF:97": "TP-Link",
    "64:70:02": "TP-Link",
    "6C:5A:B0": "TP-Link",
    "74:DA:88": "TP-Link",
    "A0:F3:C1": "TP-Link",
    "B0:BE:76": "TP-Link",
    "C0:06:C3": "TP-Link",
    "EC:08:6B": "TP-Link",
    "F4:EC:38": "TP-Link",
    # Philips Hue / Signify
    "00:17:88": "Philips Hue",
    "EC:B5:FA": "Philips Hue",
    # Sonos
    "00:0E:58": "Sonos",
    "34:7E:5C": "Sonos",
    "48:A6:B8": "Sonos",
    "54:2A:1B": "Sonos",
    "78:28:CA": "Sonos",
    "94:9F:3E": "Sonos",
    "B8:E9:37": "Sonos",
    # Ring
    "00:62:6E": "Ring",
    "2C:AA:8E": "Ring",
    "FC:99:47": "Ring",
    # Intel (common in laptops/desktops)
    "00:02:B3": "Intel",
    "00:03:47": "Intel",
    "00:04:23": "Intel",
    "00:07:E9": "Intel",
    "00:0E:0C": "Intel",
    "00:0E:35": "Intel",
    "00:12:F0": "Intel",
    "00:13:02": "Intel",
    "00:13:20": "Intel",
    "00:13:CE": "Intel",
    "00:13:E8": "Intel",
    "00:15:17": "Intel",
    "00:16:76": "Intel",
    "00:16:EA": "Intel",
    "00:16:EB": "Intel",
    "00:18:DE": "Intel",
    "00:19:D1": "Intel",
    "00:1B:21": "Intel",
    "00:1C:BF": "Intel",
    "00:1D:E0": "Intel",
    "00:1E:64": "Intel",
    "00:1E:67": "Intel",
    "00:1F:3B": "Intel",
    "00:1F:3C": "Intel",
    "00:21:5C": "Intel",
    "00:21:6A": "Intel",
    "00:22:FA": "Intel",
    "00:23:14": "Intel",
    "00:23:8B": "Intel",
    "00:24:D7": "Intel",
    "8C:EC:4B": "Intel",
    "A4:C3:F0": "Intel",
}


def lookup_oui(mac: str) -> str:
    """
    Given a MAC address string, return the manufacturer name or 'Unknown'.
    Handles formats: AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABBCCDDEEFF
    """
    if not mac:
        return "Unknown"

    mac = mac.upper().replace("-", ":").replace(".", ":")

    # normalize to XX:XX:XX:XX:XX:XX if it came in without separators
    if ":" not in mac and len(mac) == 12:
        mac = ":".join(mac[i:i+2] for i in range(0, 12, 2))

    parts = mac.split(":")
    if len(parts) < 3:
        return "Unknown"

    prefix = ":".join(parts[:3])
    return OUI_TABLE.get(prefix, "Unknown")
