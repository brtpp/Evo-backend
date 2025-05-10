import re
import json
import uuid
from datetime import datetime

# --- New security deps ---
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pwn import cyclic, p64

# existing imports...
import sympy as sp
import numpy as np
from scipy.integrate import odeint
from pint import UnitRegistry

from code_writer import generate_tool, generate_sys_monitor
from product_builder import build_product
from affiliate_engine import match_affiliate_offer
from performance_tracker import score_output

ureg = UnitRegistry()
LOG_FILE = "performance_log.json"

def initialize_log():
    try:
        with open(LOG_FILE, "x") as f:
            json.dump([], f)
    except FileExistsError:
        pass

initialize_log()

def detect_domain(prompt: str) -> str:
    pl = prompt.lower()
    domains = {
        # … your existing domains …
        "development":   ["function","class","script","api","deploy","code"],
        "medical":       ["diagnosis","symptom","treatment","disease","medicine"],
        # NEW: top-tier hacker domains
        "security-advanced": [
            "disassemble","exploit","shellcode","overflow","ctf","vuln","reverse"
        ],
    }
    for d, keys in domains.items():
        if any(k in pl for k in keys):
            return d
    return "general"

def analyze_behavior(data: dict) -> str:
    # … your existing code …

def apply_tone_filter(text: str, tone: str) -> str:
    # … your existing code …

def log_score(item_id, clicked=False, converted=False, time_on_page=0):
    # … your existing code …

# ———————— SECURITY-ADVANCED HANDLERS ————————

def handle_reverse_engineering(hex_string: str) -> str:
    """
    Disassembles a hex payload (e.g. '48 89 e5 ...') into x86_64 instructions.
    """
    # strip non-hex, split on spaces
    bytes_list = bytes.fromhex(re.sub(r'[^0-9a-fA-F ]', '', hex_string))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    disasm = "\n".join(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}"
                       for insn in md.disasm(bytes_list, 0x1000))
    return f"Disassembly:\n{disasm or '[no instructions found]'}"

def handle_exploit_development(prompt: str) -> str:
    """
    Returns a skeleton buffer-overflow exploit using pwntools.
    """
    # simple example: user asked for "buffer overflow exploit skeleton"
    offset =  cyclic(200).find(b"aaaa")  # demonstration only
    shellcode_addr = "0xdeadbeef"        # placeholder; user should adjust
    skeleton = f"""
from pwn import *

# adjust these:
elf = ELF('./vuln_binary')
p = process(elf.path)
payload = b"A" * {offset} + p64({shellcode_addr})
p.sendline(payload)
p.interactive()
"""
    return skeleton.strip()

# ———————— Main Entry Point ————————

def process_prompt(prompt: str, tier: str="free", behavior: dict=None) -> dict:
    dom = detect_domain(prompt)
    tone = analyze_behavior(behavior or {})
    pl = prompt.lower()

    # … existing branches …

    # 5) Security-advanced domain
    if dom == "security-advanced":
        # reverse-engineering?
        if "disassemble" in pl:
            # assume user typed: "disassemble <hex data>"
            _, hex_data = prompt.split(" ", 1)
            resp = handle_reverse_engineering(hex_data)
            score_output("reverse_engineering", time_on_page=10)
            return {"response": apply_tone_filter(resp, tone)}

        # exploit development?
        if "exploit" in pl or "overflow" in pl:
            resp = handle_exploit_development(prompt)
            score_output("exploit_skeleton", time_on_page=15)
            return {"response": apply_tone_filter(resp, tone)}

    # … fallback and other domains …

    return {"response": apply_tone_filter(
        "What would you like me to build or find for you today?", tone
    )}
