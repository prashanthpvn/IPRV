import csv
import networkx as nx
import numpy as np
import requests
import itertools
from random import *
import random
from operator import itemgetter
import math
import operator
import time
import sys
import re
from collections import OrderedDict
import ipaddress
from datetime import datetime, timedelta


result=  'bgp-data-path.csv' 
#bw_details = 'BW_OF_LINKS.csv'
fp = open(result, 'a')
fp.write("Type, Prefix, S-AS, D-AS \n")

pfx = '10.0.0.0/8' ### initial prefix from which subnets for each node is derived ###########
net = ipaddress.ip_network(pfx)

N = int(sys.argv[1])  ## number of nodes in Internet AS graph
#P = int(sys.argv[2])  ### number of prefixes per node


G = nx.random_internet_as_graph(N)
#print (G.edges(), G.nodes())

prefix_graphs = {}


prefix_len = math.ceil(math.log(N,2))
#print (prefix_len)
subnets = list(net.subnets(prefixlen_diff=prefix_len))

node_prefixes = {}

for i in G.nodes():
	node_prefixes[i] = str(subnets[i])

print (node_prefixes)


########### assign transactions data #############################################
for i in node_prefixes:
	fp.write(str('assign')+ "," + str(node_prefixes[i]) + "," + str(65536) +  "," + str(i) + "," + "\n")
################################################################################

############ generate path transactions upto length 4 starting from each node ###############

def generate_data(origin,prefix):
	H = nx.DiGraph()
	#print (i, list(G.neighbors(s)))
	#visited = [False] * len(G.nodes())
	forwarded = {}
	for node in G.nodes():
		forwarded[node] = False
	queue = []
	queue.append((origin,0)) ### node and depth
	H.add_node(origin)
	#prefix = node_prefixes[origin]
	prefix_received_from_neighbors = {}
	for node in G.nodes():
		prefix_received_from_neighbors[node] = [] ### {1:[2,3]} store from which nodes u received prefix dont send it to them
	while queue:
		#print (queue)
		(s,d) = queue.pop(0)
		#print ('vertex,depth',s,d)
		if forwarded[s] == False:
			if (d <= 4):
				for i in list(G.neighbors(s)):
					if i not in list(set(prefix_received_from_neighbors[s])):
						H.add_edge(s,i)
						path = nx.shortest_path(H, source = origin, target = s) #### path from origin till node s ##
						fp.write(str('announce')+ "," + str(prefix) + "," + str(s) + "," + str(i) + ", " + str(path) + "," + "\n")
						print ('s, neighbor, prefix', s, i, path, prefix)
						queue.append((i,d+1))
						prefix_received_from_neighbors[i].append(s)
					#if (visited[i] == False):
					#visited[s] = True
			else:
				break
			forwarded[s] = True

def main():
	#global node_prefixes
	for i in G.nodes():
		prefix = node_prefixes[i]
		generate_data(i,prefix)
	#for i in G.nodes():
		#print ('neighbors of', i, list(G.neighbors(i)))


main()
fp.close()
