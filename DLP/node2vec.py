import numpy as np
import networkx as nx
import random
from gensim.models import Word2Vec
import os


'''
得到 node2vec 编码
'''


def alias_setup(probs):
    K = len(probs)
    q = np.zeros(K)
    J = np.zeros(K, dtype=np.int)

    # 1. 使用 1 * K 的矩形框起来
    smaller = []
    larger = []
    for kk, prob in enumerate(probs):
        q[kk] = K * prob
        if q[kk] < 1.0:
            smaller.append(kk)
        else:
            larger.append(kk)

    # 2. 挪，把大的块切分移到小的块上
    while len(smaller) > 0 and len(larger) > 0:
        small = smaller.pop()
        large = larger.pop()

        J[small] = large
        q[large] = q[large] + q[small] - 1.0
        if q[large] < 1.0:
            smaller.append(large)
        else:
            larger.append(large)

    return J, q


# 采样
def alias_draw(J, q):
    K = len(J)

    # 1. 选定第几列
    kk = int(np.floor(np.random.rand() * K))
    # 2. 在某一列中选定某一行
    if np.random.rand() < q[kk]:
        return kk
    else:
        return J[kk]


def get_alias_edge(G, p, q, src, dst):
    unnormalized_probs = []
    for dst_nbr in sorted(G.neighbors(dst)):
        if dst_nbr == src:  # if d == 0
            unnormalized_probs.append(G[dst][dst_nbr]['weight'] / p)
        elif G.has_edge(dst_nbr, src):  # if d == 1
            unnormalized_probs.append(G[dst][dst_nbr]['weight'])
        else:  # if d == 2
            unnormalized_probs.append(G[dst][dst_nbr]['weight'] / q)
    norm_const = sum(unnormalized_probs)
    normalized_probs = [float(u_prob) / norm_const for u_prob in unnormalized_probs]

    return alias_setup(normalized_probs)


def node2vec_walk(G, alias_nodes, alias_edges, walk_length, start_node):
    walk = [start_node]

    while len(walk) < walk_length:
        cur = walk[-1]
        # 在邻居中采样
        cur_nbrs = sorted(G.neighbors(cur))
        if len(cur_nbrs) > 0:
            if len(walk) == 1:
                # 第一步没有参考，只能从节点中采样
                next_step = cur_nbrs[alias_draw(alias_nodes[cur][0], alias_nodes[cur][1])]
                walk.append(next_step)
            else:
                # 之后使用 node2vec 的方式进行采样
                prev = walk[-2]
                next_step = cur_nbrs[alias_draw(alias_edges[(prev, cur)][0],
                                                alias_edges[(prev, cur)][1])]
                walk.append(next_step)
        else:
            break

    return walk


def learn_embeddings(walks):
    walks = [map(str, walk) for walk in walks]
    model = Word2Vec(walks, size=128, window=10, min_count=0, sg=1, workers=8)
    return model


def node2vec(G):
    # Read Single Graph
    for edge in G.edges():
        G[edge[0]][edge[1]]['weight'] = 1

    # Preprocess Transition Probs
    alias_nodes = {}
    for node in G.nodes():
        unnormalized_probs = [G[node][nbr]['weight'] for nbr in sorted(G.neighbors(node))]
        norm_const = sum(unnormalized_probs)
        # 普通随机游走的转移概率
        normalized_probs = [float(u_prob) / norm_const for u_prob in unnormalized_probs]
        # 更快地采样邻居节点
        alias_nodes[node] = alias_setup(normalized_probs)

    alias_edges = {}

    for edge in G.edges():
        alias_edges[edge] = get_alias_edge(G, 1, 1, edge[0], edge[1])

    # Simulate Walks
    num_walks = 16
    walk_length = 50
    walks = []
    nodes = list(G.nodes)
    for walk_iter in range(num_walks):
        # print(f"{walk_iter + 1} / {num_walks}")
        random.shuffle(nodes)  # 随机选择一个开始
        for node in nodes:
            walk_result = node2vec_walk(G, alias_nodes, alias_edges, walk_length, start_node=node)
            if len(walk_result) < 3:
                continue
            walks.append(walk_result)
    return walks


def main():
    pass
    # G = load_graph(...)
    # walks = node2vec(G)
    # learn_embeddings(walks)


if __name__ == '__main__':
    main()
