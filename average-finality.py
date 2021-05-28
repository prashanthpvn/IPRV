import csv
import networkx as nx
import numpy as np
import requests
import itertools
#from bitstring import BitArray
from random import *
import random
from operator import itemgetter
import math
import operator
import time
import sys
import re
from collections import OrderedDict
from datetime import datetime, timedelta

#edge_list = [(1,2),(1,3),(1,4),(2,3),(2,4),(3,4)]

n = int(sys.argv[1]) # nodes
m = int(sys.argv[2]) # random seed or[ edges to attach to each node (preferential attachment) for barabasi albert ]
#seed_value = int(sys.argv[3]) ## seed value
G = nx.barabasi_albert_graph(n,m)

# random.seed(seed_value)
# np.random.seed(seed_value)

#G = nx.random_internet_as_graph(n)

#G = nx.Graph()
# G.add_edge(1, 2, delay=3)
# G.add_edge(1, 3, delay=6)
# G.add_edge(1, 4, delay=9)
# G.add_edge(2, 4, delay=5)
# G.add_edge(3, 4, delay=1)
# G.add_edge(2, 3, delay=2)


#G.add_edges_from(edge_list)

for (u, v) in G.edges():
        #G.edge[u][v]['bw'] = np.random.randint(initial_bw, initial_bw+1)
        G[u][v]['delay'] = np.random.randint(10,40)

sum_of_degrees = 0
for i in G.nodes():
	sum_of_degrees = sum_of_degrees + G.degree(i)

average_degree = math.ceil(float(sum_of_degrees)/float(len(G.nodes())))

result = 'avg_finality:'+str(n)+':'+str(m)+':'+str(average_degree)+':'+'.csv'
fp = open(result, 'a')
#fr = open(times_with_seed, 'a')

print ("degree,average_degree", average_degree)

#print (G.edges(data=True))

# class node(): # 
#     def __init__(self):
#         self.visited = False
#         self.forwarded = False 
#         self.reached_time = 0        


def finality_time_with_verifiction(s,vf_time):
	#print ('in finality function')
	forwarded = {}
	for node in G.nodes():
		forwarded[node] = False
	tx_reached_time = {}
	tx_reached_time[s] = 0
	queue = []
	queue.append(s)
	while (queue):
		s = queue.pop(0)
		#print ('popped element', s)
		if forwarded[s] == False:
			for i in G.neighbors(s):
				if forwarded[i] == False:
					queue.append(i)
					#print ('queue', queue)
					if i not in tx_reached_time:
						tx_reached_time[i] = tx_reached_time[s]+ G[s][i]['delay']+vf_time
					else:
						if ((tx_reached_time[s] + G[s][i]['delay']) < tx_reached_time[i]):
							tx_reached_time[i] = tx_reached_time[s]+ G[s][i]['delay']+vf_time
					#print ('tx_reached_time', tx_reached_time)
			forwarded[s] = True
	return tx_reached_time	
	

def finality_time(s):
	#print ('in finality function')
	forwarded = {}
	for node in G.nodes():
		forwarded[node] = False
	tx_reached_time = {}
	tx_reached_time[s] = 0
	queue = []
	queue.append(s)
	while (queue):
		s = queue.pop(0)
		#print ('popped element', s)
		if forwarded[s] == False:
			for i in G.neighbors(s):
				if forwarded[i] == False:
					queue.append(i)
					#print ('queue', queue)
					if i not in tx_reached_time:
						tx_reached_time[i] = tx_reached_time[s]+ G[s][i]['delay']
					else:
						if ((tx_reached_time[s] + G[s][i]['delay']) < tx_reached_time[i]):
							tx_reached_time[i] = tx_reached_time[s]+ G[s][i]['delay']
					#print ('tx_reached_time', tx_reached_time)
			forwarded[s] = True
	return tx_reached_time	


def main():
	sum_times = 0.0
	random_node_list = random.sample(list(G.nodes()), 100)
	print (random_node_list)
	for i in random_node_list:
		reached_time_with_verifiction = finality_time_with_verifiction(i,1)
		sort_reached_times_with_verification = sorted(reached_time_with_verifiction.items(), key=lambda x: x[1], reverse=True)
		print (sort_reached_times_with_verification[0][1])
		sum_times = sum_times+sort_reached_times_with_verification[0][1]
		fp.write( str(i)+ "," + str(sort_reached_times_with_verification[0][1]) +  "," + "\n")
	average_finality = float(sum_times) / float( len(random_node_list) )
	print (average_finality)
	fp.write(str('average_finality')+ "," + str(average_finality) +  "," + "\n")

main()
print ('done')

#




