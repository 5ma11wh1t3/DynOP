import json
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.patches import FancyBboxPatch, Circle
import numpy as np
from matplotlib.colors import LinearSegmentedColormap
import sys
from common_paths import ANALYZE_DIR, add_base_x86_to_syspath

add_base_x86_to_syspath()

try:
    import find_stack_pivot
    import find_reg_gadget_chain
except ImportError:
    print("Import Error")
    exit(1)

def plot_gadget_filtering(dataset, binary):
    file_fold = f'{dataset}'
    gadgets_info = find_reg_gadget_chain.info_init(binary[:-4], file_fold)

    gadgets_dict = gadgets_info.gadgets_dict

    controllable_reg = gadgets_info.controllable_regs
    target_regs = [_['reg_name'] for _ in gadgets_info.target_regs]

    edges = find_reg_gadget_chain.get_edges(gadgets_dict, controllable_reg, target_regs)

    if edges is None:
        return None

    edges = find_reg_gadget_chain.sort_edges(gadgets_info, edges)

    if edges is None:
        return None

    # Extract filtered gadget addresses
    filtered_gadget_addrs = set([edge['addr'] for edge in edges])

    print(f"Total gadgets before filtering: {len(gadgets_dict)}")
    print(f"Total gadgets after filtering: {len(filtered_gadget_addrs)}")
    print(f"Reduction rate: {(1 - len(filtered_gadget_addrs) / len(gadgets_dict)) * 100:.2f}%")

    # ===== Figure 1: show all gadgets =====
    all_addrs = list(gadgets_dict.keys())
    filtered_count = len([addr for addr in all_addrs if addr in filtered_gadget_addrs])

    print(f"\nFull visualization:")
    print(f"Before filtering: {len(all_addrs)}")
    print(f"After filtering: {filtered_count}")

    # ===== Figure 1: compare before and after filtering (all gadgets)=====
    fig1 = plt.figure(figsize=(12, 12))
    ax1 = fig1.add_subplot(111)

    # ax1.set_title(f'Gadgets Filtering Comparison - {dataset}\n'
    #               f'Before: {len(gadgets_dict):,} | After: {len(filtered_gadget_addrs):,} | '
    #               f'Filtered: {(1 - len(filtered_gadget_addrs) / len(gadgets_dict)) * 100:.1f}%',
    #               fontsize=16, fontweight='bold', pad=20)
    ax1.set_facecolor('#f8f9fa')

    # Compute grid layout
    total_gadgets = len(all_addrs)
    cols = int(np.sqrt(total_gadgets * 1.5))  # Slightly wider layout
    rows = (total_gadgets + cols - 1) // cols
    box_size = min(0.8, 50 / max(rows, cols))  # Adaptive size

    print(f"Grid layout: {rows} rows x {cols} cols")

    # Draw all gadgets
    for i, addr in enumerate(all_addrs):
        row = i // cols
        col = i % cols
        x = col * (box_size + 0.1)
        y = (rows - row - 1) * (box_size + 0.1)

        # Choose color based on whether the gadget is in the filtered set
        if addr in filtered_gadget_addrs:
            color = '#ff4444'  # bright red
            alpha = 1.0
            linewidth = 0.3
            edgecolor = '#cc0000'
        else:
            color = '#e0e0e0'  # light gray
            alpha = 0.4
            linewidth = 0
            edgecolor = '#cccccc'

        rect = FancyBboxPatch((x, y), box_size, box_size,
                            boxstyle="round,pad=0.02",
                            linewidth=linewidth,
                            edgecolor=edgecolor,
                            facecolor=color,
                            alpha=alpha)
        ax1.add_patch(rect)

    ax1.set_xlim(-0.5, cols * (box_size + 0.1))
    ax1.set_ylim(-0.5, rows * (box_size + 0.1))
    ax1.set_aspect('equal')
    ax1.axis('off')

    # Add a cleaner legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#ff4444', alpha=1.0, edgecolor="#000000", linewidth=2,
            label=f'Potential Gadgets: {filtered_count:,} ({filtered_count/len(all_addrs)*100:.1f}%)'),
        Patch(facecolor='#e0e0e0', alpha=0.4, edgecolor="#000000", linewidth=2,
            label=f'Filtered Out: {len(all_addrs) - filtered_count:,} ({(1-filtered_count/len(all_addrs))*100:.1f}%)')
    ]
    ax1.legend(handles=legend_elements, loc='upper center', bbox_to_anchor=(0.5, -0.02),
            fontsize=24, frameon=False, ncol=2)

    plt.tight_layout()
    fig1.savefig(ANALYZE_DIR / 'Figure6.png',
                dpi=200, bbox_inches='tight', facecolor='white')
    # plt.show()

    print(f"\n✓ Figure 6 saved to: {ANALYZE_DIR / 'Figure6.png'}")


def plot_gadget_dependency(dataset, binary):
    file_fold = f'{dataset}'
    gadgets_info = find_reg_gadget_chain.info_init(binary[:-4], file_fold)

    gadgets_dict = gadgets_info.gadgets_dict

    controllable_reg = gadgets_info.controllable_regs
    target_regs = [_['reg_name'] for _ in gadgets_info.target_regs]

    edges = find_reg_gadget_chain.get_edges(gadgets_dict, controllable_reg, target_regs)

    if edges is None:
        return None

    edges = find_reg_gadget_chain.sort_edges(gadgets_info, edges)

    if edges is None:
        return None

    # Extract filtered gadget addresses
    filtered_gadget_addrs = set([edge['addr'] for edge in edges])

    print(f"Total gadgets before filtering: {len(gadgets_dict)}")
    print(f"Total gadgets after filtering: {len(filtered_gadget_addrs)}")
    print(f"Reduction rate: {(1 - len(filtered_gadget_addrs) / len(gadgets_dict)) * 100:.2f}%")

    # ===== Figure 2: filtered gadget dependency graph (including rsp)=====
    fig2 = plt.figure(figsize=(16, 16))
    ax2 = fig2.add_subplot(111)

    # ax2.set_title(f'Gadget Dependencies Graph - {dataset}\n'
            #   f'Register Dependencies with RSP as Starting Point',
            #   fontsize=18, fontweight='bold', pad=20)
    ax2.set_facecolor('#f8f9fa')

    # Create directed graph
    G = nx.DiGraph()

    # Build register-to-gadget mapping
    register_to_gadgets = {}  # {register: [gadget_addrs]}

    for edge in edges:
        addr = edge['addr']
        dst = edge['dst']
        src = edge['src']
        rip = edge['rip']

        # Add nodes (including rsp)
        if addr not in G:
            G.add_node(addr, register=dst)

        # Record which gadgets have a given register as dst
        if dst not in register_to_gadgets:
            register_to_gadgets[dst] = []
        register_to_gadgets[dst].append(addr)

    # Add rsp as the start node
    G.add_node('rsp', register='rsp')

    # Add edges from rsp to all gadgets whose src or rip is rsp
    for edge in edges:
        addr = edge['addr']
        src = edge['src']
        rip = edge['rip']

        if src == 'rsp':
            G.add_edge('rsp', addr, via='src')
        if rip == 'rsp':
            G.add_edge('rsp', addr, via='rip')

    # Add edges between gadgets: dst points to gadgets with matching src/rip
    for edge in edges:
        addr = edge['addr']
        dst = edge['dst']
        src = edge['src']
        rip = edge['rip']

        # Find src or rip values matching another gadget dst
        for target_addr in register_to_gadgets.get(src, []):
            if target_addr != addr:
                G.add_edge(addr, target_addr, via=src)

        for target_addr in register_to_gadgets.get(rip, []):
            if target_addr != addr:
                G.add_edge(addr, target_addr, via=rip)

    # If the graph is too large, select key nodes
    if len(G.nodes()) > 100:
        # BFS from rsp and select the first 100 nodes
        bfs_nodes = list(nx.bfs_tree(G, 'rsp', depth_limit=4).nodes())[:100]
        G = G.subgraph(bfs_nodes).copy()

    print(f"\nGraph statistics:")
    print(f"Nodes: {len(G.nodes())}")
    print(f"Edges: {len(G.edges())}")

    # Use spring layout to distribute nodes evenly
    if len(G.nodes()) > 0:
        # Use spring layout with a larger k to spread nodes out
        pos = nx.spring_layout(G, k=3, iterations=100, seed=42)

        # Draw edges first so nodes are layered above them
        # Use a special color for edges from rsp
        rsp_edges = [(u, v) for u, v in G.edges() if u == 'rsp']
        other_edges = [(u, v) for u, v in G.edges() if u != 'rsp']

        # Draw edges from rsp (blue, thicker)
        nx.draw_networkx_edges(G, pos, edgelist=rsp_edges,
                            edge_color='#4169E1', arrows=True,
                            arrowsize=20, width=3, alpha=0.7, ax=ax2,
                            connectionstyle='arc3,rad=0.1',
                            arrowstyle='-|>', node_size=1500)

        # Draw other edges (light gray)
        nx.draw_networkx_edges(G, pos, edgelist=other_edges,
                            edge_color="#a5a4a4", arrows=True,
                            arrowsize=12, width=1.2, alpha=0.4, ax=ax2,
                            connectionstyle='arc3,rad=0.1',
                            arrowstyle='-|>', node_size=1500)

        # Determine the register corresponding to each node
        node_registers = {}
        node_registers['rsp'] = 'rsp'
        for node in G.nodes():
            if node != 'rsp':
                for edge in edges:
                    if edge['addr'] == node:
                        node_registers[node] = edge['dst'].lower()
                        break

        # Classify nodes: rsp, highlighted registers (rdi, rsi, rdx, rcx), others
        highlight_regs = {'rdi', 'rsi', 'rdx', 'rcx'}

        rsp_node = ['rsp']
        highlight_nodes = [n for n in G.nodes() if n != 'rsp' and node_registers.get(n) in highlight_regs]
        other_nodes = [n for n in G.nodes() if n != 'rsp' and node_registers.get(n) not in highlight_regs]

        # Draw the rsp node (gold circle, largest)
        nx.draw_networkx_nodes(G, pos, nodelist=rsp_node,
                            node_color='#FFD700', node_size=2500,
                            alpha=1.0, ax=ax2,
                            node_shape='o', edgecolors='#FF8C00', linewidths=4)

        # Draw highlighted register nodes (different colors)
        if highlight_nodes:
            highlight_colors = {
                'rdi': '#FF6B6B',  # red
                'rsi': '#4ECDC4',  # cyan
                'rdx': '#95E1D3',  # light green
                'rcx': '#F38181'   # pink
            }
            for node in highlight_nodes:
                reg = node_registers.get(node, '')
                color = highlight_colors.get(reg, '#ff4444')
                nx.draw_networkx_nodes(G, pos, nodelist=[node],
                                    node_color=color, node_size=1200,
                                    alpha=0.9, ax=ax2,
                                    edgecolors='#333333', linewidths=2.5)

        # Draw other nodes (gray)
        if other_nodes:
            nx.draw_networkx_nodes(G, pos, nodelist=other_nodes,
                                node_color='#AAAAAA', node_size=800,
                                alpha=0.6, ax=ax2,
                                edgecolors='#666666', linewidths=1.5)

        # Draw labels
        labels = {}
        for node in G.nodes():
            if node == 'rsp':
                labels[node] = 'RSP'
            else:
                labels[node] = node_registers.get(node, '?').upper()

        # rsp label (black, bold, large)
        nx.draw_networkx_labels(G, pos, {k: v for k, v in labels.items() if k == 'rsp'},
                            font_size=14, font_weight='bold', font_color='black', ax=ax2)

        # Highlighted register labels (white, bold)
        if highlight_nodes:
            nx.draw_networkx_labels(G, pos, {k: v for k, v in labels.items() if k in highlight_nodes},
                                font_size=11, font_weight='bold', font_color='black', ax=ax2)

        # Other node labels (white, normal)
        if other_nodes:
            nx.draw_networkx_labels(G, pos, {k: v for k, v in labels.items() if k in other_nodes},
                                font_size=9, font_weight='normal', font_color='black', ax=ax2)
    else:
        ax2.text(0.5, 0.5, 'No dependencies found',
                ha='center', va='center', fontsize=16,
                transform=ax2.transAxes, color='#666666')

    ax2.axis('off')
    ax2.set_aspect('equal')

    # Add legend
    from matplotlib.lines import Line2D
    legend_elements2 = [
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#FFD700',
            markersize=18+6, label='RSP (Start)', markeredgecolor='#FF8C00', markeredgewidth=6),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#FF6B6B',
            markersize=14+6, label='RDI', markeredgecolor='#333333', markeredgewidth=4),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#4ECDC4',
            markersize=14+6, label='RSI', markeredgecolor='#333333', markeredgewidth=4),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#95E1D3',
            markersize=14+6, label='RDX', markeredgecolor='#333333', markeredgewidth=4),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#F38181',
            markersize=14+6, label='RCX', markeredgecolor='#333333', markeredgewidth=4),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#AAAAAA',
            markersize=12+6, label='Other Registers', markeredgecolor='#666666', markeredgewidth=3, alpha=0.6),
        Line2D([0], [0], color='#4169E1', linewidth=6, label='From RSP', alpha=0.7),
        Line2D([0], [0], color="#a5a4a4", linewidth=2.4, label='Between Gadgets', alpha=0.4)
    ]
    ax2.legend(handles=legend_elements2, loc='upper center', bbox_to_anchor=(0.5, -0.02),
            fontsize=27, frameon=False, ncol=4)

    plt.tight_layout()
    fig2.savefig(ANALYZE_DIR / 'Figure7.png',
                dpi=200, bbox_inches='tight', facecolor='white')
    # plt.show()

    print(f"✓ Figure 7 saved to: {ANALYZE_DIR / 'Figure7.png'}")

if __name__ == "__main__":

    dataset = 'centos-7.1810'
    binary = 'addconn.bin'

    plot_gadget_filtering(dataset, binary)
    plot_gadget_dependency(dataset, binary)

