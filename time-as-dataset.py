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

seed_value = int(sys.argv[1]) ## seed value
edge_list = []
with open('/home/prashanth/Documents/FSD2L-Evaluation/fsd2l-code/202203.as-rel.txt', 'r') as f:
	reader = csv.reader(f, dialect='excel', delimiter='|')
	for row in reader:
		edge_list.append((int(row[0]),int(row[1])))

#print ('edges of as-relationships.txt file',edge_list)
G = nx.Graph()
G.add_edges_from(list(set(edge_list)))
print ('no of edges',len(G.edges()))
print ('no of nodes',len(G.nodes()))
print('G is connected:',nx.is_connected(G))
degree_list = []
for i in G.nodes():
	degree_list.append(G.degree(i))
	#print (G.degree(i))
print ('number of nodes, max, min, avg degrees of G', len(G.nodes()), max(degree_list), min(degree_list), sum(degree_list)/len(degree_list))

to_be_removed = [x for  x in G.nodes() if G.degree(x) == 1]

#print (to_be_removed)
for x in to_be_removed:
    G.remove_node(x)

print (len(G.nodes()))

result = 'time-as-relationships.csv'
fp = open(result, 'a')

for (u, v) in G.edges():
        #G.edge[u][v]['bw'] = np.random.randint(initial_bw, initial_bw+1)
        G[u][v]['delay'] = np.random.randint(10,40)

def finality_time_with_verification(s,vf_time):
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
	origin = random.choice(list(G.nodes()))
	print ('origin',origin)
	reached_time_with_verification = finality_time_with_verification(origin,1)
	reached_time = finality_time(1)
	#print (reached_time_with_verifiction, reached_time)
	#print (reached_time, len(reached_time.keys()))
	all_final_times = [ v for _, v in reached_time_with_verification.items() if v!=0]
	avg_time = sum(all_final_times)/len(all_final_times)
	fp.write(str(seed_value) + "," + str(min(all_final_times)) + "," + str(avg_time) + "," + str(max(all_final_times)) +  "," + "\n") 

main()
print ('done')
