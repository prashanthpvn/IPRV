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

result = 'time_variations:'+str(n)+':'+str(m)+':'+str(average_degree)+':'+'.csv'
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
	reached_time_with_verifiction = finality_time_with_verifiction(1,1)
	reached_time = finality_time(1)
	#print (reached_time_with_verifiction, reached_time)
	#print (reached_time, len(reached_time.keys()))
	sort_reached_times = sorted(reached_time.items(), key=lambda x: x[1], reverse=True)
	sort_reached_times_with_verification = sorted(reached_time_with_verifiction.items(), key=lambda x: x[1], reverse=True)
	print (sort_reached_times[0][1], sort_reached_times_with_verification[0][1])
	#print (sort_reached_times)
	#fp.write( str(seed_value)+ "," + str(sort_reached_times_with_verification[0][1]) +  "," + "\n") 

	sum_times = 0

	all_times = {}
	#print (reached_time)

	for i in reached_time_with_verifiction:
		#print (reached_time[i])
		if reached_time_with_verifiction[i] in all_times:
			all_times[reached_time_with_verifiction[i]] = all_times[reached_time_with_verifiction[i]]+1
		else:
			all_times[reached_time_with_verifiction[i]] = 1

	#print ('all_times', all_times)


	for i in (all_times.keys()):
		sum_times = sum_times+all_times[i]

	#print (sum_times)

	temp = 0.0
	for i in (sorted(all_times.keys())):
		fp.write( str(i)+ "," + str( ( (float(all_times[i])/float(sum_times)) + float(temp)) ) +  "," + "\n") 
		#print  i, scores_trust[i], float(scores_trust[i])/float(sum_scores_tqr), ( (float(scores_trust[i])/float(sum_scores_tqr)) + float(temp)) 
		temp = temp + ( float(all_times[i]) / float( sum_times ) ) ### cumulatively add all values score[i]/sum_score





main()
print ('done')

#




