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

    # 提取过滤后的 gadget 地址
    filtered_gadget_addrs = set([edge['addr'] for edge in edges])

    print(f"Total gadgets before filtering: {len(gadgets_dict)}")
    print(f"Total gadgets after filtering: {len(filtered_gadget_addrs)}")
    print(f"Reduction rate: {(1 - len(filtered_gadget_addrs) / len(gadgets_dict)) * 100:.2f}%")

    # ===== 图1: 显示所有 gadgets =====
    all_addrs = list(gadgets_dict.keys())
    filtered_count = len([addr for addr in all_addrs if addr in filtered_gadget_addrs])

    print(f"\nFull visualization:")
    print(f"Before filtering: {len(all_addrs)}")
    print(f"After filtering: {filtered_count}")

    # ===== 图1: 过滤前后对比（全部 gadgets）=====
    fig1 = plt.figure(figsize=(12, 12))
    ax1 = fig1.add_subplot(111)

    # ax1.set_title(f'Gadgets Filtering Comparison - {dataset}\n'
    #               f'Before: {len(gadgets_dict):,} | After: {len(filtered_gadget_addrs):,} | '
    #               f'Filtered: {(1 - len(filtered_gadget_addrs) / len(gadgets_dict)) * 100:.1f}%', 
    #               fontsize=16, fontweight='bold', pad=20)
    ax1.set_facecolor('#f8f9fa')

    # 计算网格布局
    total_gadgets = len(all_addrs)
    cols = int(np.sqrt(total_gadgets * 1.5))  # 稍微宽一点的布局
    rows = (total_gadgets + cols - 1) // cols
    box_size = min(0.8, 50 / max(rows, cols))  # 自适应大小

    print(f"Grid layout: {rows} rows x {cols} cols")

    # 绘制所有 gadgets
    for i, addr in enumerate(all_addrs):
        row = i // cols
        col = i % cols
        x = col * (box_size + 0.1)
        y = (rows - row - 1) * (box_size + 0.1)
        
        # 根据是否在过滤后的集合中选择颜色
        if addr in filtered_gadget_addrs:
            color = '#ff4444'  # 鲜艳的红色
            alpha = 1.0
            linewidth = 0.3
            edgecolor = '#cc0000'
        else:
            color = '#e0e0e0'  # 浅灰色
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

    # 添加更美观的图例
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

    # 提取过滤后的 gadget 地址
    filtered_gadget_addrs = set([edge['addr'] for edge in edges])

    print(f"Total gadgets before filtering: {len(gadgets_dict)}")
    print(f"Total gadgets after filtering: {len(filtered_gadget_addrs)}")
    print(f"Reduction rate: {(1 - len(filtered_gadget_addrs) / len(gadgets_dict)) * 100:.2f}%")

    # ===== 图2: 过滤后的 Gadget 依赖关系图（包含 rsp）=====
    fig2 = plt.figure(figsize=(16, 16))
    ax2 = fig2.add_subplot(111)

    # ax2.set_title(f'Gadget Dependencies Graph - {dataset}\n'
            #   f'Register Dependencies with RSP as Starting Point', 
            #   fontsize=18, fontweight='bold', pad=20)
    ax2.set_facecolor('#f8f9fa')

    # 创建有向图
    G = nx.DiGraph()

    # 构建寄存器到 gadget 的映射
    register_to_gadgets = {}  # {register: [gadget_addrs]}

    for edge in edges:
        addr = edge['addr']
        dst = edge['dst']
        src = edge['src']
        rip = edge['rip']
        
        # 添加节点（包括 rsp）
        if addr not in G:
            G.add_node(addr, register=dst)
        
        # 记录哪些 gadget 的 dst 是某个寄存器
        if dst not in register_to_gadgets:
            register_to_gadgets[dst] = []
        register_to_gadgets[dst].append(addr)

    # 添加 rsp 作为起点节点
    G.add_node('rsp', register='rsp')

    # 添加边：从 rsp 指向所有 src 或 rip 是 rsp 的 gadget
    for edge in edges:
        addr = edge['addr']
        src = edge['src']
        rip = edge['rip']
        
        if src == 'rsp':
            G.add_edge('rsp', addr, via='src')
        if rip == 'rsp':
            G.add_edge('rsp', addr, via='rip')

    # 添加 gadget 之间的边：dst 连向 src/rip 匹配的 gadget
    for edge in edges:
        addr = edge['addr']
        dst = edge['dst']
        src = edge['src']
        rip = edge['rip']
        
        # 查找 src 或 rip 匹配其他 gadget 的 dst
        for target_addr in register_to_gadgets.get(src, []):
            if target_addr != addr:
                G.add_edge(addr, target_addr, via=src)
        
        for target_addr in register_to_gadgets.get(rip, []):
            if target_addr != addr:
                G.add_edge(addr, target_addr, via=rip)

    # 如果图太大，选择关键节点
    if len(G.nodes()) > 100:
        # 从 rsp 开始的 BFS，选择前 100 个节点
        bfs_nodes = list(nx.bfs_tree(G, 'rsp', depth_limit=4).nodes())[:100]
        G = G.subgraph(bfs_nodes).copy()

    print(f"\nGraph statistics:")
    print(f"Nodes: {len(G.nodes())}")
    print(f"Edges: {len(G.edges())}")

    # 使用 spring layout 使节点均匀分布
    if len(G.nodes()) > 0:
        # 使用 spring layout，k 值调大使节点更分散
        pos = nx.spring_layout(G, k=3, iterations=100, seed=42)
        
        # 绘制边（先画，这样节点在上层）
        # 从 rsp 出发的边用特殊颜色
        rsp_edges = [(u, v) for u, v in G.edges() if u == 'rsp']
        other_edges = [(u, v) for u, v in G.edges() if u != 'rsp']
        
        # 绘制从 rsp 出发的边（蓝色，较粗）
        nx.draw_networkx_edges(G, pos, edgelist=rsp_edges, 
                            edge_color='#4169E1', arrows=True, 
                            arrowsize=20, width=3, alpha=0.7, ax=ax2,
                            connectionstyle='arc3,rad=0.1',
                            arrowstyle='-|>', node_size=1500)
        
        # 绘制其他边（浅灰色）
        nx.draw_networkx_edges(G, pos, edgelist=other_edges,
                            edge_color="#a5a4a4", arrows=True, 
                            arrowsize=12, width=1.2, alpha=0.4, ax=ax2,
                            connectionstyle='arc3,rad=0.1',
                            arrowstyle='-|>', node_size=1500)
        
        # 确定每个节点对应的寄存器
        node_registers = {}
        node_registers['rsp'] = 'rsp'
        for node in G.nodes():
            if node != 'rsp':
                for edge in edges:
                    if edge['addr'] == node:
                        node_registers[node] = edge['dst'].lower()
                        break
        
        # 分类节点：rsp, 高亮寄存器(rdi, rsi, rdx, rcx), 其他
        highlight_regs = {'rdi', 'rsi', 'rdx', 'rcx'}
        
        rsp_node = ['rsp']
        highlight_nodes = [n for n in G.nodes() if n != 'rsp' and node_registers.get(n) in highlight_regs]
        other_nodes = [n for n in G.nodes() if n != 'rsp' and node_registers.get(n) not in highlight_regs]
        
        # 绘制 rsp 节点（金黄色圆形，最大）
        nx.draw_networkx_nodes(G, pos, nodelist=rsp_node,
                            node_color='#FFD700', node_size=2500, 
                            alpha=1.0, ax=ax2, 
                            node_shape='o', edgecolors='#FF8C00', linewidths=4)
        
        # 绘制高亮寄存器节点（不同颜色）
        if highlight_nodes:
            highlight_colors = {
                'rdi': '#FF6B6B',  # 红色
                'rsi': '#4ECDC4',  # 青色
                'rdx': '#95E1D3',  # 浅绿色
                'rcx': '#F38181'   # 粉红色
            }
            for node in highlight_nodes:
                reg = node_registers.get(node, '')
                color = highlight_colors.get(reg, '#ff4444')
                nx.draw_networkx_nodes(G, pos, nodelist=[node],
                                    node_color=color, node_size=1200, 
                                    alpha=0.9, ax=ax2, 
                                    edgecolors='#333333', linewidths=2.5)
        
        # 绘制其他节点（灰色）
        if other_nodes:
            nx.draw_networkx_nodes(G, pos, nodelist=other_nodes,
                                node_color='#AAAAAA', node_size=800, 
                                alpha=0.6, ax=ax2, 
                                edgecolors='#666666', linewidths=1.5)
        
        # 绘制标签
        labels = {}
        for node in G.nodes():
            if node == 'rsp':
                labels[node] = 'RSP'
            else:
                labels[node] = node_registers.get(node, '?').upper()
        
        # rsp 标签（黑色，粗体，大字）
        nx.draw_networkx_labels(G, pos, {k: v for k, v in labels.items() if k == 'rsp'}, 
                            font_size=14, font_weight='bold', font_color='black', ax=ax2)
        
        # 高亮寄存器标签（白色，粗体）
        if highlight_nodes:
            nx.draw_networkx_labels(G, pos, {k: v for k, v in labels.items() if k in highlight_nodes}, 
                                font_size=11, font_weight='bold', font_color='black', ax=ax2)
        
        # 其他节点标签（白色，正常）
        if other_nodes:
            nx.draw_networkx_labels(G, pos, {k: v for k, v in labels.items() if k in other_nodes}, 
                                font_size=9, font_weight='normal', font_color='black', ax=ax2)
    else:
        ax2.text(0.5, 0.5, 'No dependencies found', 
                ha='center', va='center', fontsize=16, 
                transform=ax2.transAxes, color='#666666')

    ax2.axis('off')
    ax2.set_aspect('equal')

    # 添加图例
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
    
