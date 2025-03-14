import angr
import networkx as nx
from collections import Counter
import sys

def analyze_binary(binary_path):
    print(f"[*] Analyzing binary: {binary_path}")
    project = angr.Project(binary_path, auto_load_libs=False)
    print("[*] Generating CFG...")
    cfg = project.analyses.CFGFast(normalize=True)
    graph = cfg.graph
    num_nodes = len(graph.nodes())
    print(f"[+] Number of nodes in the graph: {num_nodes}")
    num_edges = len(graph.edges())
    print(f"[+] Number of edges in the graph: {num_edges}")
    instruction_types = Counter()
    for node in graph.nodes():
        if isinstance(node, angr.knowledge_plugins.cfg.cfg_node.CFGNode):
            block = project.factory.block(node.addr, node.size)
            for instr in block.capstone.insns:
                instruction_types[instr.mnemonic] += 1
    print(f"[+] Number of different instruction types: {len(instruction_types)}")
    print("[*] Instruction type distribution:")
    for instr_type, count in instruction_types.most_common(10):
        print(f"  {instr_type}: {count}")
    dot_file = binary_path + ".cfg.dot"
    print(f"[*] Exporting CFG to {dot_file}...")
    nx_graph = nx.DiGraph()
    for src, dst in graph.edges():
        src_addr = hex(src.addr) if hasattr(src, 'addr') else str(src)
        dst_addr = hex(dst.addr) if hasattr(dst, 'addr') else str(dst)
        nx_graph.add_edge(src_addr, dst_addr)
    for node in graph.nodes():
        if hasattr(node, 'addr'):
            node_str = hex(node.addr)
            if node_str not in nx_graph:
                nx_graph.add_node(node_str)
            if hasattr(node, 'name') and node.name:
                nx_graph.nodes[node_str]['label'] = f"{node.name}: {node_str}"
            else:
                nx_graph.nodes[node_str]['label'] = node_str
    nx.drawing.nx_pydot.write_dot(nx_graph, dot_file)
    print(f"[+] CFG exported to {dot_file}")
    return {
        'num_nodes': num_nodes,
        'num_edges': num_edges,
        'num_instruction_types': len(instruction_types),
        'instruction_types': instruction_types,
        'dot_file': dot_file
    }

def gen(binary_path):
    results = analyze_binary(binary_path)
    print("\n[*] Summary:")
    print(f"[+] 1. Number of nodes: {results['num_nodes']}")
    print(f"[+] 2. Number of edges: {results['num_edges']}")
    print(f"[+] 3. Number of different instruction types: {results['num_instruction_types']}")
    print(f"[+] CFG dot file: {results['dot_file']}")