import os
import sys

def test():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, 'reference', 'meta.yaml'),
        os.path.join(script_dir, '..', 'reference', 'meta.yaml'),
        'tests/reference/meta.yaml',
        'reference/meta.yaml'
    ]
    meta_path = None
    for c in candidates:
        if os.path.isfile(c):
            meta_path = c
            break

    if not meta_path:
        print("Error: meta.yaml not found", file=sys.stderr)
        sys.exit(1)

    with open(meta_path, 'r', encoding='utf-8') as f:
        payload = f.read()

    p_start = payload.find("proxies:")
    if p_start == -1: return
    p_start += 8
    if p_start < len(payload) and payload[p_start] == '\r': p_start += 1
    if p_start < len(payload) and payload[p_start] == '\n': p_start += 1

    next_section = -1
    search_pos = p_start
    while True:
        search_pos = payload.find('\n', search_pos)
        if search_pos == -1: break
        search_pos += 1
        if search_pos < len(payload) and payload[search_pos].isalpha():
            next_section = search_pos
            break

    p_end = next_section if next_section != -1 else len(payload)
    block = payload[p_start:p_end]

    filtered_block = ""
    raw_clash_names = ""
    search_start = 0

    while True:
        name_pos = block.find("- name:", search_start)
        if name_pos == -1: break

        node_start = name_pos
        while node_start > 0 and block[node_start - 1] in ' \t':
            node_start -= 1

        next_name_pos = block.find("- name:", name_pos + 7)
        next_node_start = len(block)
        if next_name_pos != -1:
            next_node_start = next_name_pos
            while next_node_start > node_start and block[next_node_start - 1] in ' \t':
                next_node_start -= 1

        node_str = block[node_start:next_node_start]

        if "xhttp" not in node_str:
            filtered_block += node_str
            n_pos = node_str.find("- name:")
            end_line = node_str.find('\n', n_pos)
            if end_line == -1: end_line = len(node_str)
            q_start = n_pos + 7
            while q_start < end_line and node_str[q_start] in " \t'\"": q_start += 1
            q_end = end_line - 1
            while q_end >= q_start and node_str[q_end] in " \t\r\n'\"": q_end -= 1
            if q_start <= q_end:
                raw_clash_names += "      - \"" + node_str[q_start:q_end + 1] + "\"\n"
        search_start = next_name_pos

    print("--- FILTERED BLOCK ---")
    print(filtered_block)
    print("--- NAMES ---")
    print(raw_clash_names)

test()
