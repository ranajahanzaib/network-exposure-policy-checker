#!/usr/bin/env python3
"""
Generate authentic, high-resolution terminal showcase screenshots for Network Exposure Policy Checker.
Renders macOS terminal aesthetic with dark theme and syntax highlighting.
"""

import os
from PIL import Image, ImageDraw, ImageFont

FONT_PATH = "/System/Library/Fonts/Menlo.ttc"
BOLD_FONT_PATH = "/System/Library/Fonts/Supplemental/Courier New Bold.ttf" if os.path.exists("/System/Library/Fonts/Supplemental/Courier New Bold.ttf") else FONT_PATH

# Colors
BG_COLOR = (13, 17, 23)        # #0d1117 (GitHub dark canvas)
TERMINAL_BG = (22, 27, 34)     # #161b22 (GitHub dark surface)
TITLE_BG = (33, 38, 45)        # #21262d
BORDER_COLOR = (48, 54, 61)    # #30363d
TEXT_DEFAULT = (201, 209, 217) # #c9d1d9
TEXT_MUTED = (139, 148, 158)   # #8b949e
PROMPT_USER = (88, 166, 255)   # #58a6ff
PROMPT_SYM = (126, 231, 135)   # #7ee787
COMMAND_COLOR = (240, 246, 252)# #f0f6fc
GREEN = (63, 185, 80)          # #3fb950 (allow, connected, valid)
RED = (248, 81, 73)            # #f85149 (deny, violation, critical, high)
YELLOW = (210, 153, 34)        # #d29922 (medium, warning)
CYAN = (56, 139, 253)          # #388bfd (zone, id)
PURPLE = (188, 140, 255)       # #bc8cff (schema, rule)

BTN_RED = (255, 95, 86)
BTN_YELLOW = (255, 189, 46)
BTN_GREEN = (39, 201, 63)

def parse_line_spans(line):
    """Tokenize line into (text, color) tuples for syntax highlighting."""
    if line.startswith("$ "):
        return [
            ("$ ", PROMPT_SYM),
            (line[2:], COMMAND_COLOR)
        ]
    if line.startswith("[exit "):
        return [(line, RED)]
    
    # Header lines
    if "Network Exposure Policy Checker" in line:
        return [("Network Exposure Policy Checker", PROMPT_USER), (line[31:], TEXT_DEFAULT)]
    if line.startswith("Deployment:") or line.startswith("Snapshot:") or line.startswith("Plan ") or line.startswith("Valid policy:"):
        parts = line.split(":", 1)
        return [(parts[0] + ":", TEXT_MUTED), (parts[1], CYAN if "Snapshot" in line or "Plan" in line else GREEN)]
    if line.startswith("SERVICE / ENDPOINT"):
        return [(line, TEXT_MUTED)]
    if line == "FINDINGS":
        return [(line, (240, 246, 252))]

    # Table rows
    for zone in ["local", "lan", "vpn", "internet"]:
        if f" {zone} " in line:
            parts = line.split()
            if len(parts) >= 4:
                endpoint = parts[0]
                z = parts[1]
                intent = parts[2]
                observed = " ".join(parts[3:])
                
                intent_color = GREEN if intent == "allow" else RED
                obs_color = TEXT_MUTED
                if observed == "violation":
                    obs_color = RED
                elif observed == "connected":
                    obs_color = GREEN
                elif "refused" in observed:
                    obs_color = YELLOW
                
                row = f"{endpoint:<24} {z:<10} "
                return [
                    (f"{endpoint:<24} ", TEXT_DEFAULT),
                    (f"{z:<10} ", CYAN),
                    (f"{intent:<7} ", intent_color),
                    (observed, obs_color)
                ]

    # Findings
    for sev, color in [("critical", RED), ("high", RED), ("medium", YELLOW), ("info", TEXT_MUTED)]:
        if line.startswith(f"{sev} ") or line.startswith(f"{sev:<6} "):
            parts = line.split(maxsplit=3)
            if len(parts) >= 4:
                return [
                    (f"{parts[0]:<6} ", color),
                    (f"{parts[1]} ", CYAN),
                    (f"{parts[2]}: ", TEXT_DEFAULT),
                    (parts[3], COMMAND_COLOR)
                ]

    # JSON highlighting
    if any(k in line for k in ['"version"', '"$schema"', '"runs"', '"tool"', '"driver"', '"rules"', '"results"', '"ruleId"', '"level"', '"message"', '"properties"']):
        # Simple JSON key highlight
        tokens = []
        in_str = False
        buf = ""
        for char in line:
            if char == '"':
                buf += char
                if in_str:
                    in_str = False
                    if buf.endswith('":'):
                        tokens.append((buf, CYAN))
                    else:
                        tokens.append((buf, GREEN if "PI" in buf or "2.1.0" in buf else TEXT_DEFAULT))
                    buf = ""
                else:
                    if buf:
                        tokens.append((buf, TEXT_MUTED))
                        buf = ""
                    in_str = True
            else:
                buf += char
        if buf:
            tokens.append((buf, TEXT_MUTED))
        return tokens

    return [(line, TEXT_DEFAULT)]

def render_terminal_image(title, lines, output_path, scale=2):
    font_size = 14 * scale
    line_height = int(22 * scale)
    pad_x = 24 * scale
    pad_y = 20 * scale
    title_height = 38 * scale

    font = ImageFont.truetype(FONT_PATH, font_size)
    title_font = ImageFont.truetype(FONT_PATH, int(12 * scale))

    # Calculate content width
    max_len = max(len(l) for l in lines)
    char_w = font.getlength("M")
    content_w = int(max_len * char_w) + pad_x * 2
    content_w = max(content_w, 760 * scale)
    content_h = title_height + pad_y + len(lines) * line_height + pad_y

    img = Image.new("RGBA", (content_w, content_h), TERMINAL_BG)
    draw = ImageDraw.Draw(img)

    # Title bar
    draw.rectangle([(0, 0), (content_w, title_height)], fill=TITLE_BG)
    draw.line([(0, title_height), (content_w, title_height)], fill=BORDER_COLOR, width=scale)

    # Traffic light buttons
    btn_radius = int(6 * scale)
    btn_y = title_height // 2
    draw.ellipse([(16 * scale, btn_y - btn_radius), (16 * scale + btn_radius * 2, btn_y + btn_radius)], fill=BTN_RED)
    draw.ellipse([(34 * scale, btn_y - btn_radius), (34 * scale + btn_radius * 2, btn_y + btn_radius)], fill=BTN_YELLOW)
    draw.ellipse([(52 * scale, btn_y - btn_radius), (52 * scale + btn_radius * 2, btn_y + btn_radius)], fill=BTN_GREEN)

    # Title text
    t_w = title_font.getlength(title)
    draw.text(((content_w - t_w) // 2, (title_height - int(12 * scale)) // 2), title, fill=TEXT_MUTED, font=title_font)

    # Terminal output
    curr_y = title_height + pad_y
    for line in lines:
        spans = parse_line_spans(line)
        curr_x = pad_x
        for text, color in spans:
            draw.text((curr_x, curr_y), text, fill=color, font=font)
            curr_x += int(font.getlength(text))
        curr_y += line_height

    # Outer border
    draw.rectangle([(0, 0), (content_w - 1, content_h - 1)], outline=BORDER_COLOR, width=scale)

    # Downscale smoothly to 1x with antialiasing
    final_w = content_w // scale
    final_h = content_h // scale
    final_img = img.resize((final_w, final_h), Image.Resampling.LANCZOS)
    final_img.save(output_path, "PNG", optimize=True)
    print(f"Generated {output_path} ({final_w}x{final_h})")

def main():
    os.makedirs("docs/screenshots", exist_ok=True)

    # 1. overview.png - Primary Hero Showcase
    overview_lines = [
        "$ network-exposure-policy-checker audit --policy portintent.yaml --snapshot snapshot.json --evidence local-evidence.json",
        "Network Exposure Policy Checker v0.1.0",
        "Deployment: basic-stack",
        "Snapshot: d5fe919edfde4e860c910b82cf4179adce65cf9bc9b82c95ace36416e3dfdbe9",
        "",
        "SERVICE / ENDPOINT       ZONE       INTENT  OBSERVED",
        "postgres/database        local      allow   refused_on_tested_targets",
        "postgres/database        lan        deny    not_tested",
        "postgres/database        vpn        deny    not_tested",
        "postgres/database        internet   deny    not_tested",
        "redis/cache              local      allow   refused_on_tested_targets",
        "redis/cache              lan        deny    not_tested",
        "redis/cache              vpn        deny    not_tested",
        "redis/cache              internet   deny    not_tested",
        "api/http                 local      allow   refused_on_tested_targets",
        "api/http                 lan        allow   not_tested",
        "api/http                 vpn        allow   not_tested",
        "api/http                 internet   allow   not_tested",
        "admin/dashboard          local      allow   refused_on_tested_targets",
        "admin/dashboard          lan        deny    not_tested",
        "admin/dashboard          vpn        allow   not_tested",
        "admin/dashboard          internet   deny    not_tested",
        "",
        "FINDINGS",
        "medium PI003 api: required endpoint refused all tested connections",
        "info   PI006 -: lan: 0/4 planned targets observed",
        "info   PI006 -: vpn: 0/4 planned targets observed",
        "info   PI006 -: internet: 0/4 planned targets observed",
    ]
    render_terminal_image("network-exposure-policy-checker audit — Safe Baseline Matrix", overview_lines, "docs/screenshots/overview.png")

    # 2. audit-violation.png - Confirmed Reachability Violation
    violation_lines = [
        "$ network-exposure-policy-checker audit --policy portintent.yaml --snapshot snapshot.json --evidence local-evidence.json --evidence lan-evidence.json --fail-on high",
        "Network Exposure Policy Checker v0.1.0",
        "Deployment: basic-stack",
        "Snapshot: d5fe919edfde4e860c910b82cf4179adce65cf9bc9b82c95ace36416e3dfdbe9",
        "",
        "SERVICE / ENDPOINT       ZONE       INTENT  OBSERVED",
        "postgres/database        local      allow   refused_on_tested_targets",
        "postgres/database        lan        deny    refused_on_tested_targets",
        "postgres/database        vpn        deny    not_tested",
        "postgres/database        internet   deny    not_tested",
        "redis/cache              local      allow   refused_on_tested_targets",
        "redis/cache              lan        deny    violation",
        "redis/cache              vpn        deny    not_tested",
        "redis/cache              internet   deny    not_tested",
        "api/http                 local      allow   refused_on_tested_targets",
        "api/http                 lan        allow   refused_on_tested_targets",
        "api/http                 vpn        allow   not_tested",
        "api/http                 internet   allow   not_tested",
        "admin/dashboard          local      allow   refused_on_tested_targets",
        "admin/dashboard          lan        deny    refused_on_tested_targets",
        "admin/dashboard          vpn        allow   not_tested",
        "admin/dashboard          internet   deny    not_tested",
        "",
        "FINDINGS",
        "high   PI001 redis: forbidden TCP connection succeeded from declared lan source",
        "medium PI003 api: required endpoint refused all tested connections",
        "info   PI006 -: vpn: 0/4 planned targets observed",
        "info   PI006 -: internet: 0/4 planned targets observed",
        "",
        "[exit 1: finding threshold exceeded (high >= high)]",
    ]
    render_terminal_image("network-exposure-policy-checker audit — Confirmed Policy Violation (PI001)", violation_lines, "docs/screenshots/audit-violation.png")

    # 3. workflow-pipeline.png - 5-Step Operational Flow
    workflow_lines = [
        "# 1. Validate declared multi-zone network reachability policy",
        "$ network-exposure-policy-checker policy validate --file portintent.yaml",
        "Valid policy: basic-stack (4 services)",
        "",
        "# 2. Inspect Docker Compose port publishing & container configuration",
        "$ network-exposure-policy-checker inspect --policy portintent.yaml --config-only --output snapshot.json",
        "Snapshot d5fe919edfde4e860c910b82cf4179adce65cf9bc9b82c95ace36416e3dfdbe9: 4 bindings, runtime not inspected",
        "",
        "# 3. Compute immutable cryptographic probe plan",
        "$ network-exposure-policy-checker plan --policy portintent.yaml --snapshot snapshot.json --output plan.json",
        "Plan 4cf844f1d1b418f0582c78e8b1a873432e5f974c7af450c4a694f79076499b69: 16 exact targets",
        "",
        "# 4. Dry-run planned probes across target vantage point",
        "$ network-exposure-policy-checker probe --plan plan.json --vantage local --dry-run",
        "127.0.0.1:5432 local postgres/database",
        "127.0.0.1:6379 local redis/cache",
        "127.0.0.1:8080 local api/http",
        "127.0.0.1:4000 local admin/dashboard",
        "",
        "# 5. Execute authorized probe and record portable evidence",
        "$ network-exposure-policy-checker probe --plan plan.json --vantage local --output local-evidence.json",
        "Wrote 4 observations to local-evidence.json",
    ]
    render_terminal_image("network-exposure-policy-checker — 5-Stage Verification Workflow", workflow_lines, "docs/screenshots/workflow-pipeline.png")

    # 4. sarif-integration.png - SARIF Output for GitHub Code Scanning
    sarif_lines = [
        "$ network-exposure-policy-checker audit --policy portintent.yaml --snapshot snapshot.json --evidence local-evidence.json --format sarif",
        "{",
        '  "version": "2.1.0",',
        '  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",',
        '  "runs": [',
        "    {",
        '      "tool": {',
        '        "driver": {',
        '          "name": "Network Exposure Policy Checker",',
        '          "version": "0.1.0",',
        '          "rules": [',
        '            { "id": "PI001", "name": "Confirmed unintended reachability" },',
        '            { "id": "PI002", "name": "Potentially overbroad binding" },',
        '            { "id": "PI003", "name": "Required endpoint unavailable" },',
        '            { "id": "PI004", "name": "Unresolved configuration" },',
        '            { "id": "PI005", "name": "Unexpected port mapping" },',
        '            { "id": "PI006", "name": "Incomplete coverage" },',
        '            { "id": "PI007", "name": "Unsupported networking" }',
        "          ]",
        "        }",
        "      },",
        '      "results": [',
        "        {",
        '          "ruleId": "PI003",',
        '          "level": "warning",',
        '          "message": { "text": "required endpoint refused all tested connections" },',
        '          "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "portintent.yaml" } } }],',
        '          "partialFingerprints": { "network-exposure-policy-checker/v1": "9a1bf185...d201" },',
        '          "properties": { "confidence": "confirmed", "zone": "local" }',
        "        }",
        "      ]",
        "    }",
        "  ]",
        "}",
    ]
    render_terminal_image("network-exposure-policy-checker audit — SARIF 2.1.0 CI/CD Report", sarif_lines, "docs/screenshots/sarif-integration.png")

if __name__ == "__main__":
    main()
