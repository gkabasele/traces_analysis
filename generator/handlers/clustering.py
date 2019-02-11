#!/usr/bin/python
import random
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import scipy as sp
import scipy.stats as stats
import pdb
import heapq
from collections import OrderedDict

class Cluster(object):

    def __init__(self, flows):
        self.flows = frozenset([flows])

    def compute_distance(self, other, distances):
        try:
            mindist = 1
            for f in self.flows:
                for g in other.flows:
                    if g in distances[f]:
                        mindist =  min(distances[f][g], mindist)

                    else:
                        mindist = min(distances[g][f], mindist)
            return mindist
        except KeyError:
            pdb.set_trace()

    def merge_cluster(self, other):
        self.flows = self.flows | other.flows

    def __repr__(self):
        return str(self)

    def __str__(self):
        s = ""
        for f in self.flows:
            s+= " " + str(f) + "\n"
        return s

    def __hash__(self):
        return hash(self.flows)

    def __eq__(self, other):
        return self.flows == other.flows

    def __len__(self):
        return len(self.flows)

class ClusterNode(object):

    def __init__(self, flow_a, flow_b, dist):
        self.flow_a = flow_a
        self.flow_b = flow_b
        self.dist = dist

    def __lt__(self, other):
        return self.dist < other.dist

    def __le__(self, other):
        return self.dist <= other.dist

    def __gt__(self, other):
        return self.dist > other.dist

    def __ge__(self, other):
        return self.dist >= other.dist

    def __eq__(self, other):
        return self.dist == other.dist

def find_min_dist_clusters(clusters, distances):

    index_i = 0
    index_j = 0
    mindist = 1

    for i in range(len(clusters)):
        for j in range(i+1, len(clusters)):
            f = clusters[i]
            g = clusters[j]
            d = f.compute_distance(g, distances)
            if d < mindist:
                mindist = d
                index_i = i
                index_j = j

    return index_i, index_j, mindist

def compute_all_min_distance_dict(distances):

    min_dists = OrderedDict()

    for i in distances:
        if i in min_dists:
            min_d = min_dists[i].dist
        else:
            min_d = 1

        for j in distances[i]:
            d = distances[i][j]

            if d < min_d:
                min_dists[i] = ClusterNode(i, j, d)
                if ((j not in min_dists) or 
                        (j in min_dists and d < min_dists[j].dist)):
                    min_dists[j] = ClusterNode(i, j, d)
    return min_dists

def compute_all_min_distance_heap(distances):

    min_dists = []
    for i in distances:
        flow_a = i
        if len(distances[i].keys()) > 0:
            flow_b = distances[i].keys()[0]
            min_d = distances[i][flow_b]

            for j in distances[i]:
                d = distances[i][j]

                if d < min_d:
                    min_d = d
                    flow_b = j

            heapq.heappush(min_dists, ClusterNode(flow_a, flow_b, min_d))
    return min_dists

def clusters_from_flows(clusters, fa, fb):
    cluster_a = None 
    cluster_b = None
    for c in clusters:
        if fa in c.flows:
            cluster_a = c
        if fb in c.flows:
            cluster_b = c

        if not(cluster_a is None or cluster_b is None):
            return cluster_a, cluster_b
    if cluster_a is None or cluster_b is None:
        raise ValueError("{} or {} does no belong to a cluster")
'''
Cluster Algorithm
-----------------
Input:  List of distances for each flow based on kolmogorov-smirnov test, L
        List of flows, F    
        Find minimum distances function, d
Output: List of cluster

Algo:
    clusters: { cluster(f) | forall f in F }

    while |cluster| > 1:
        a , b = d(cluster)
        cluster.remojve(a, b)
        cluster.add(cluster(a, b))
    return cluster
'''

def clustering(distances, n, dist):

    clusters = [Cluster(x) for x in distances.keys()]
    min_dists = compute_all_min_distance_heap(distances)
    min_d = 0

    while len(clusters) > n and min_d < dist:
        c = heapq.heappop(min_dists)
        min_d = c.dist
        cluster_a, cluster_b = clusters_from_flows(clusters, c.flow_a, c.flow_b)
        cluster_a.merge_cluster(cluster_b)
        clusters.remove(cluster_b)
    return clusters
