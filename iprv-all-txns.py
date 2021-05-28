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
import csv
import collections

import eth_keys, os
import hashlib
from ecies import encrypt, decrypt
from eth_account.messages import defunct_hash_message
from web3.auto import w3
from hexbytes import HexBytes
#from datetime import datetime, timedelta
import datetime
import ipaddress

# n = int(sys.argv[1]) # nodes
# m = int(sys.argv[2]) # edges to attach to each node (preferential attachment)
seed_value = int(sys.argv[1])  ## seed value

random.seed(seed_value)
np.random.seed(seed_value)

ir_asn = 65536

peer_ids = {} 

def generate_key_pair():
	sk = eth_keys.keys.PrivateKey(os.urandom(32))
	pk = sk.public_key
	address = pk.to_checksum_address()
	return sk,pk,address

def update_peer_ids(asn):
	sk,pk,address = generate_key_pair()
	peer_ids[asn] = {'sk':sk,'pk':pk,'address':address}

#G = nx.barabasi_albert_graph(n,m)

#RIR_Provider = {} ### RIR to provider - prefixes, start date, end date ########

dag_ledger = {}

asn2pfx_list = {}  ##  { owner_asn : {prefix1: {provider_asn,start_date,end_date}}, 
pfx2as = {}

RIR_P_C = {} ### {P1: {cust1:prefix, cust2: prefix}, P2:{cust1:prefix, cust2:prefix} } ########

genesis_tx_ids = []


pfx_graph = {} ####### {prefix:Graph object} e.g pfx_graph['1.1.1.1/16'] = nx.DiGraph() ########3

result=  'fsd2l.csv'
fp = open(result, 'a')

#### verify signature - passing signature and ethereum account address of the AS/node ###############

def verify_signature(signature, message_hash, address):
	retrieved_eth_address = w3.eth.account.recoverHash(message_hash, signature= HexBytes(signature))
	#print ("retrieved_eth_address",retrieved_eth_address)
	if retrieved_eth_address == address:
		return True
	else:
		return False

#######################return tx_obj ########################################################################

#### msg and secret key of the corresponding AS/node to sign- return signature #######################

def sign(encoded_msg,sk): 
    #encoded_msg = msg.encode()
    message_hash = defunct_hash_message(encoded_msg)
    eth_account_privatekey = HexBytes(sk.to_hex())      ######### convert to hex
    signed_message = w3.eth.account.signHash(message_hash,private_key=eth_account_privatekey)
    signature = bytes(signed_message.signature)
    return signature
#####################################################################################################


class tx(): # 
    def __init__(self, tx_id, tx_type, tip1_tx_id, tip2_tx_id, tx_info, time_stamp, signature):
        self.tx_id = tx_id
        self.tx_type = tx_type
        #self.address = address ## public key (ethereum address) of the tx creator
        self.tip1_tx_id = tip1_tx_id
        self.tip2_tx_id = tip2_tx_id
        self.tx_info = tx_info
        self.time_stamp = time_stamp
        self.signature = signature


def create_allocate_transaction(asn, tx_type, tip1_tx_id, tip2_tx_id, tx_info):
	time_stamp = time.time()	
	tx_id_msg = str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(tx_info)+str(time_stamp)
	tx_id = hashlib.sha256(tx_id_msg.encode()).hexdigest()
	#print ('tx_id',tx_id)
	msg = str(tx_id)+str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(tx_info)+str(time_stamp)
	#print ("nonce_msg in create transaction",msg)
	encoded_msg = msg.encode()
	tx_signature = {} ## dict to hold multiple signatures
	double_spend = False
	sk = peer_ids[asn]['sk']
	signature = sign(encoded_msg, sk) ## signature using private key of asn

	if asn == ir_asn:
		tx_signature[asn] = signature
	else:
		tx_signature[asn] = signature ## signature of asn
		
	#################### verify double spending (by RIR) and sign ###################################################
		pfx_in_tx = ipaddress.ip_network(tx_info['prefix'])
		already_allocated = False
		#print ("RIR_P_C",RIR_P_C)
		#if len(RIR_P_C) != 0:
		allocated_asn = 0
		if (asn in RIR_P_C):
			for i in RIR_P_C[asn]:
				pfx_customer = ipaddress.ip_network(RIR_P_C[asn][i]['prefix'])
				if pfx_in_tx.overlaps(pfx_customer):
					already_allocated =  True
					allocated_asn = i
	########### adding RIR signature to the transaction ################################		
		if (not already_allocated):
			sk_rir = peer_ids[ir_asn]['sk']
			signature_rir = sign(encoded_msg, sk_rir) ## signature using private key of asn
			tx_signature[ir_asn] = signature_rir
		else:
			double_spend = True
			print ("Invalid Transaction: Duplicate allocation of prefix (double spending)")
			print ("Prefix " + str(pfx_in_tx)+ ' is already allocated to '+str(allocated_asn))
    ##################################################################################
	# 	sk_rir = peer_ids[ir_asn]['sk']
	# 	signature_rir = sign(encoded_msg,sk_rir)

	#########################  creating a tx_obj from the values of tx #####################################
	if (not double_spend):
		tx_obj = tx(tx_id, tx_type, tip1_tx_id, tip2_tx_id, tx_info, time_stamp, tx_signature)
		return tx_obj
	else:
		return None
	#return tx_obj
    ################################################################################################################

############## udpate ledger and asn2pfx list after verifying PoA and history ###########################################################
def update_ledger(tx_obj):
	tx_info = tx_obj.tx_info
	pfx = tx_info['prefix']
	customer_asn = tx_info['d-as']
	provider_asn = tx_info['s-as']
	#print ("Allocate Transaction from AS " + str(provider_asn) + 'to AS ' + str(customer_asn))
	tx_msg = str(tx_obj.tx_id)+str(tx_obj.tx_type)+str(tx_obj.tip1_tx_id)+str(tx_obj.tip2_tx_id)+str(tx_obj.tx_info)+str(tx_obj.time_stamp)
	encoded_tx_msg = tx_msg.encode()
	tx_message_hash = defunct_hash_message(encoded_tx_msg)
	#print ('tx_obj.signature, tx_message_hash, tx_obj.address',tx_obj.signature, tx_message_hash, tx_obj.address)
	PoA = True
	for i in tx_obj.signature:
		signature  = tx_obj.signature[i]
		address = peer_ids[i]['address']
		#if(not verify_signature(signature, tx_message_hash, tx_obj.address)):
		if(not verify_signature(signature, tx_message_hash, address)):
			PoA = False
		else:
			print ("Signature of AS " + str(i) + ' validated successfully')
	if PoA:
		 

		if provider_asn ==  ir_asn:
			#print ("Allocate Transaction from RIR" + str(provider_asn) + 'to ASN' + str(customer_asn))
		############# udpate asn2pfx and pfx2aslist #############################################################################
			if customer_asn not in asn2pfx_list:
				asn2pfx_list[customer_asn]= {pfx:{'provider_asn':provider_asn,'start_time':tx_info['start_time'],'end_time':tx_info['end_time']}}
			else:
				asn2pfx_list[customer_asn][pfx] = {'provider_asn':provider_asn,'start_time':tx_info['start_time'],'end_time':tx_info['end_time']}
			pfx2as[pfx] = customer_asn
		################ Create pfx graph for the prefix #################################
			G = nx.DiGraph()
			pfx_graph[pfx] = G
			dag_ledger[tx_obj.tx_id] = tx_obj
			#print ('FSD2L and PFX2AS list updated')
			print ('PFX2AS-list',asn2pfx_list)
		##########################################################################################################################
		else:
			#print ('Allocate Transaction from ASN ' + str(provider_asn) + ' to ASN ' + str(customer_asn))
			pfx2 = ipaddress.ip_network(pfx)
			for p in asn2pfx_list[provider_asn]:
				pfx1 = ipaddress.ip_network(p)
				if (pfx1.overlaps(pfx2)):
					print ('History Validation: Owner ASN of ' +str(p)  + ' from pfx2aslist is ' + str(provider_asn))
					dag_ledger[tx_obj.tx_id] = tx_obj
				############# udpate pfx2aslist #############################################################################
				if customer_asn not in asn2pfx_list:
					asn2pfx_list[customer_asn]= {pfx:{'provider_asn':provider_asn,'start_time':tx_info['start_time'],'end_time':tx_info['end_time']}}
				else:
					asn2pfx_list[customer_asn][pfx] = {'provider_asn':provider_asn,'start_time':tx_info['start_time'],'end_time':tx_info['end_time']}
				###################### update provider to customer list ##################################################################
				if provider_asn in RIR_P_C:
					RIR_P_C[provider_asn][customer_asn] = {'prefix':pfx}
				else:
					RIR_P_C[provider_asn] = {customer_asn: {'prefix':pfx}}
				pfx2as[pfx] = customer_asn
				#####################################################################################################################
				################ Create pfx graph for the new prefix #################################
				G = nx.DiGraph()
				pfx_graph[pfx] = G
				#print ('FSD2L and PFX2AS list updated')
				print ('PFX2AS-List',asn2pfx_list)
				######################################################################################################
				break

#########################################################################################################
def create_revoke_OR_update_transaction(asn, tx_type, tip1_tx_id, tip2_tx_id, tx_info):

	time_stamp = time.time()	
	tx_id_msg = str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(tx_info)+str(time_stamp)
	tx_id = hashlib.sha256(tx_id_msg.encode()).hexdigest()
	#print ('tx_id',tx_id)
	msg = str(tx_id)+str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(tx_info)+str(time_stamp)
	encoded_msg = msg.encode()
	
	tx_signature = {} ## dict to hold multiple signatures
	src_asn = tx_info['s-as']
	dst_asn = tx_info['d-as']

	sk_src_asn = peer_ids[src_asn]['sk']
	signature_src_asn = sign(encoded_msg, sk_src_asn) ## signature using private key of src asn

	sk_dst_asn = peer_ids[dst_asn]['sk']
	signature_dst_asn = sign(encoded_msg, sk_dst_asn) ## signature using private key of dst asn

	tx_signature[src_asn] = signature_src_asn
	tx_signature[dst_asn] = signature_dst_asn

	tx_obj = tx(tx_id, tx_type, tip1_tx_id, tip2_tx_id, tx_info, time_stamp, tx_signature)
	return tx_obj
    

################################################################################################################

	########### create test revoke or update transction with only signature of source asn ########
#########################################################################################################
def create_test_revoke_OR_update_transaction(asn, tx_type, tip1_tx_id, tip2_tx_id, tx_info):
	time_stamp = time.time()	
	tx_id_msg = str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(tx_info)+str(time_stamp)
	tx_id = hashlib.sha256(tx_id_msg.encode()).hexdigest()
	#print ('tx_id',tx_id)
	msg = str(tx_id)+str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(tx_info)+str(time_stamp)
	encoded_msg = msg.encode()
	
	tx_signature = {} ## dict to hold multiple signatures
	src_asn = tx_info['s-as']
	dst_asn = tx_info['d-as']

	sk_src_asn = peer_ids[src_asn]['sk']
	signature_src_asn = sign(encoded_msg, sk_src_asn) ## signature using private key of src asn

	# sk_dst_asn = peer_ids[dst_asn]['sk']
	# signature_dst_asn = sign(encoded_msg, sk_dst_asn) ## signature using private key of dst asn

	tx_signature[src_asn] = signature_src_asn
	#tx_signature[dst_asn] = signature_dst_asn

	tx_obj = tx(tx_id, tx_type, tip1_tx_id, tip2_tx_id, tx_info, time_stamp, tx_signature)
	return tx_obj
    

################################################################################################################


def update_ledger_revoke_OR_update(tx_obj):
	tx_info = tx_obj.tx_info
	pfx = tx_info['prefix']
	provider_asn = tx_info['s-as']
	customer_asn = tx_info['d-as'] 

	# if tx_obj.tx_type == 'update':
	# 	print ("Update Transaction from AS " + str(provider_asn) + ' to AS ' + str(customer_asn))
	# if tx_obj.tx_type == 'revoke':
	# 	print ("Revoke Transaction from AS " + str(provider_asn) + ' to AS ' + str(customer_asn))


	tx_msg = str(tx_obj.tx_id)+str(tx_obj.tx_type)+str(tx_obj.tip1_tx_id)+str(tx_obj.tip2_tx_id)+str(tx_obj.tx_info)+str(tx_obj.time_stamp)
	encoded_tx_msg = tx_msg.encode()
	tx_message_hash = defunct_hash_message(encoded_tx_msg)
	#print ('tx_obj.signature, tx_message_hash, tx_obj.address',tx_obj.signature, tx_message_hash, tx_obj.address)
	PoA = True

	asns_from_signature_field = []
	# for i in tx_obj.signature:
	# 	asns_from_signature_field.append(i)
	asns_from_transaction = [provider_asn,customer_asn]

	for i in tx_obj.signature:
		signature  = tx_obj.signature[i]
		address = peer_ids[i]['address']
		#if(not verify_signature(signature, tx_message_hash, tx_obj.address)):
		if(not verify_signature(signature, tx_message_hash, address)):
			PoA = False
		else:
			print ("Signature of AS " + str(i) + ' validated successfully')
			asns_from_signature_field.append(i)
	if ((asns_from_signature_field == asns_from_transaction) and PoA):

	#if PoA:
		#print (customer_asn, asn2pfx_list[customer_asn][pfx]['provider_asn'])
		############### verifying the transaction from asn2pfx_list and updating the asn2pfxlist ################
		if (asn2pfx_list[customer_asn][pfx]['provider_asn'] == provider_asn):
			print ('History validation: provider of prefix ' + str(pfx) + 'from pfx2as-list is ' + str(asn2pfx_list[customer_asn][pfx]['provider_asn']))
			if tx_obj.tx_type == 'update':
				end_time = tx_info['end_time']
				#print ('end_time',end_time)
				asn2pfx_list[customer_asn][pfx]['end_time'] = end_time
				dag_ledger[tx_obj.tx_id] = tx_obj
				#print ('FSD2L and PFX2AS list updated')
				print ('PFX2ASList',asn2pfx_list)
			if tx_obj.tx_type == 'revoke':
				#del asn2pfx_list[customer_asn][pfx]
				del asn2pfx_list[customer_asn]
				del RIR_P_C[provider_asn][customer_asn]
				dag_ledger[tx_obj.tx_id] = tx_obj
				#print ('FSD2L and PFX2AS list updated')
				print ('PFX2ASList', asn2pfx_list)
	else:
		print (datetime.datetime.now())
		print ('Transaction Invalid: Signature of AS ' + str(customer_asn)+ ' is not found')
        #############################################################################################################

 #########################################################################################################
def create_announce_OR_withdraw_transaction(asn, tx_type, tip1_tx_id, tip2_tx_id, tx_info):

	time_stamp = time.time()	
	tx_id_msg = str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(tx_info)+str(time_stamp)
	tx_id = hashlib.sha256(tx_id_msg.encode()).hexdigest()
	#print ('tx_id',tx_id)
	msg = str(tx_id)+str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(tx_info)+str(time_stamp)
	encoded_msg = msg.encode()
	
	tx_signature = {} ## dict to hold multiple signatures
	src_asn = tx_info['s-as']

	sk_src_asn = peer_ids[src_asn]['sk']
	signature_src_asn = sign(encoded_msg, sk_src_asn) ## signature using private key of src asn

	tx_signature[src_asn] = signature_src_asn
	
	tx_obj = tx(tx_id, tx_type, tip1_tx_id, tip2_tx_id, tx_info, time_stamp, tx_signature)
	return tx_obj
    

################################################################################################################

def has_path(G, source, target):
    try:
        nx.shortest_path(G, source, target)
    except nx.NetworkXNoPath:
        return False
    return True



############## udpate ledger and asn2pfx list after verifying PoA and history ###########################################################
def update_ledger_announce_OR_withdraw(tx_obj):
	tx_msg = str(tx_obj.tx_id)+str(tx_obj.tx_type)+str(tx_obj.tip1_tx_id)+str(tx_obj.tip2_tx_id)+str(tx_obj.tx_info)+str(tx_obj.time_stamp)
	encoded_tx_msg = tx_msg.encode()
	tx_message_hash = defunct_hash_message(encoded_tx_msg)
	#print ('tx_obj.signature, tx_message_hash, tx_obj.address',tx_obj.signature, tx_message_hash, tx_obj.address)
	PoA = True
	for i in tx_obj.signature:
		signature  = tx_obj.signature[i]
		address = peer_ids[i]['address']
		#if(not verify_signature(signature, tx_message_hash, tx_obj.address)):
		if(not verify_signature(signature, tx_message_hash, address)):
			PoA = False
		else:
			print ("Signature of AS " + str(i) + ' validated successfully')
	if PoA:
		tx_info = tx_obj.tx_info
		pfx = tx_info['prefix']
		src_asn = tx_info['s-as']
		dst_asn = tx_info['d-as'] 
		path = tx_info['path']

		################ verify origin AS ######################
		origin_as_validation = True
		origin_asn = int(path[0])
		print ('origin ASN of ' + str(pfx) +' from pfx2as-list is '+ str(pfx2as[pfx]))
		#print ('Origin ASN of '+str(pfx)+ ' from path in transaction is '+ str(origin_asn))
		# if pfx2as[pfx] ==  origin_asn:
		# 	print ('Origin ASN validated sucessfully')
		# else:
		# 	print ("Origin ASN validation Failed")
		# 	origin_as_validation = False

		if pfx2as[pfx] !=  origin_asn:
			print ('Origin ASN validated Failed')
			origin_as_validation = False


		if origin_as_validation:			
			###### verify the path from origin AS to src_asn and add edge in pfxgraph #########
			if (tx_obj.tx_type == 'announce'):
				if len(path) == 1:
					pfx_graph[pfx].add_edge(src_asn,dst_asn)
					ints_path = list(map(int,path))
					print ('FSD2L updated successfully')
					#print ("Path " + str(ints_path)+ " validated Successfully")
				else:
					if has_path(pfx_graph[pfx], origin_asn,src_asn):
						path_from_pfxgraph = nx.shortest_path(pfx_graph[pfx], source = origin_asn, target = src_asn) #### path from origin till node s ##
						ints_path = list(map(int,path))
						print ('path_from_pfxgraph', path_from_pfxgraph)
						#print ('path_from_transaction', ints_path)
						if (path_from_pfxgraph ==  ints_path):
							#print ("Path " + str(path_from_pfxgraph) + " validated Successfully")
							############# add edge to pfxgraph ###########
							pfx_graph[pfx].add_edge(src_asn,dst_asn)
							##############################################
							dag_ledger[tx_obj.tx_id] = tx_obj
							print ('FSD2L updated successfully')
						else:
							print ("Invalid path announcement")
					else:
						print ("Invalid path announcement")
			if (tx_obj.tx_type == 'withdraw'):
				if (pfx_graph[pfx].has_edge(src_asn,dst_asn)):
					print ("History Validation: Edge from SRC_ASN to DST_ASN found in pfxgraph for prefix ", pfx)
					pfx_graph[pfx].remove_edge(src_asn, dst_asn)
					dag_ledger[tx_obj.tx_id] = tx_obj
					print ('FSD2L updated successfully')


###############################################################################################################################

def create_genesis_transaction(asn, tx_type, tip1_tx_id, tip2_tx_id, tx_info):

	time_stamp = time.time()	
	tx_id_msg = str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(tx_info)+str(time_stamp)
	tx_id = hashlib.sha256(tx_id_msg.encode()).hexdigest()
	#print ('tx_id',tx_id)
	msg = str(tx_id)+str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(tx_info)+str(time_stamp)
	encoded_msg = msg.encode()
	tx_signature = {} ## dict to hold multiple signatures
	sk = peer_ids[asn]['sk']
	signature = sign(encoded_msg, sk) ## signature using private key of asn
	tx_signature[asn] = signature
	tx_obj = tx(tx_id, tx_type, tip1_tx_id, tip2_tx_id, tx_info, time_stamp, tx_signature)
	return tx_obj



############## udpate ledger after verifying PoA ###########################################################
def update_ledger_genesis(tx_obj,value):
	############# verify if ref_tx_id is in ledger  ####################################################
	tx_msg = str(tx_obj.tx_id)+str(tx_obj.tx_type)+str(tx_obj.tip1_tx_id)+str(tx_obj.tip2_tx_id)+str(tx_obj.tx_info)+str(tx_obj.time_stamp)
	encoded_tx_msg = tx_msg.encode()
	tx_message_hash = defunct_hash_message(encoded_tx_msg)
	#print(tx_obj.tx_info)
	#print ('tx_obj.tx_info[src_asn]', asn)
	PoA = True
	for i in tx_obj.signature:
		signature  = tx_obj.signature[i]
		address = peer_ids[i]['address']
		if(not verify_signature(signature, tx_message_hash, address)):
			PoA = False
		else:
			pass
			#print ()
	if PoA:
		dag_ledger[tx_obj.tx_id] = tx_obj
		#dag_ledger['genesis' + str(value)] = tx_obj
###############################################################################################################

def select_tips(): ########### uniform random tip selection == MCMC used in POC implementation ################
    return random.sample(set(dag_ledger.keys()), 2)
#################################################################################################################

def main():
	#print ('in main')  
	update_peer_ids(ir_asn)
	#print (peer_ids)
	tx_obj = create_genesis_transaction(ir_asn,'','','',peer_ids[ir_asn])
	update_ledger_genesis(tx_obj,value=0)
	genesis_tx_ids.append(tx_obj.tx_id)
	## create another genesis transaction ###############
	tx_obj = create_genesis_transaction(ir_asn,'','','',peer_ids[ir_asn])
	update_ledger_genesis(tx_obj,value=1)
	genesis_tx_ids.append(tx_obj.tx_id)

	with open('/home/sivsai/Documents/prashanth/fsd2l/sample_path_dataset.csv', 'r') as f:
		reader = csv.reader(f, dialect='excel', delimiter=',')
		for row in reader:
			#print ('row-data',row)
			if row:
				print ("")
				#print ("")
				#print ('##################### row-data', row[0], row, '##############################')
				if (row[0] == 'assign'):
					print ("time",datetime.datetime.now())
					print ("Input:Allocate_transaction", row)
					tx_type = row[0]
					src_asn =  int(row[1])
					prefix = row[2]
					dst_asn = int(row[3])
					start_time = row[4]
					end_time = row[5]
					tx_info = {'s-as':src_asn, 'd-as':dst_asn, 'prefix': prefix, 'start_time':start_time, 'end_time':end_time}
					#print (tx_info)
					if src_asn not in peer_ids:
						update_peer_ids(src_asn)
					if dst_asn not in peer_ids:
						update_peer_ids(dst_asn)
					tip1,tip2 = select_tips()	
					if src_asn == ir_asn:
						tx_obj = create_allocate_transaction(src_asn, tx_type, dag_ledger[tip1].tx_id, dag_ledger[tip2].tx_id, tx_info)
						update_ledger(tx_obj)
					else:
						tx_obj = create_allocate_transaction(src_asn, tx_type, dag_ledger[tip1].tx_id, dag_ledger[tip2].tx_id, tx_info)
						if tx_obj:
							update_ledger(tx_obj)
						else:
							print ('')

				if (row[0] == 'revoke'):
					print ("time",datetime.datetime.now())			
					print ("Input:revoke_transaction", row)
					tx_type = row[0]
					src_asn =  int(row[1])
					prefix = row[2]
					dst_asn = int(row[3])
					tx_info = {'s-as':src_asn, 'd-as':dst_asn, 'prefix': prefix}
					tip1,tip2 = select_tips()
					tx_obj = create_test_revoke_OR_update_transaction(src_asn, tx_type, dag_ledger[tip1].tx_id, dag_ledger[tip2].tx_id, tx_info)
					update_ledger_revoke_OR_update(tx_obj)

				if (row[0] == 'update'):
						print ("time", datetime.datetime.now())
						print ("Input:update_transaction", row)
						tx_type = row[0]
						src_asn =  int(row[1])
						prefix = row[2]
						dst_asn = int(row[3])
						end_time = row[4] 
						tx_info = {'s-as':src_asn, 'd-as':dst_asn, 'prefix': prefix, 'end_time':end_time}
						tip1,tip2 = select_tips()
						tx_obj = create_revoke_OR_update_transaction(src_asn, tx_type, dag_ledger[tip1].tx_id, dag_ledger[tip2].tx_id, tx_info)
						update_ledger_revoke_OR_update(tx_obj)


				if (row[0] == 'announce'):
						tx_type = row[0]
						prefix = row[1]
						src_asn =  int(row[2])
						dst_asn = int(row[3])
						path = row[4] ## path.split() converts the path string into list of asns ex '3 4 5' to ['3', '4', '5']
						#print (prefix, src_asn, dst_asn, path.split())
						print ("time",datetime.datetime.now())
						print ("announce_transaction: Prefix, SRC_ASN, DST_ASN, PATH:", prefix,src_asn,dst_asn,path.split())
						if src_asn not in peer_ids:
							update_peer_ids(src_asn)
						if dst_asn not in peer_ids:
							update_peer_ids(dst_asn)
						tx_info = {'s-as':src_asn, 'd-as':dst_asn, 'prefix': prefix, 'path':path.split()}
						tip1,tip2 = select_tips()
						tx_obj = create_announce_OR_withdraw_transaction(src_asn, tx_type, dag_ledger[tip1].tx_id, dag_ledger[tip2].tx_id, tx_info)
						update_ledger_announce_OR_withdraw(tx_obj)

				if (row[0] == 'withdraw'):
						#print ("announce_transaction", row)
						tx_type = row[0]
						prefix = row[1]
						src_asn =  int(row[2])
						dst_asn = int(row[3])
						path = row[4] ## path.split() converts the path string into list of asns ex '3 4 5' to ['3', '4', '5']
						#print (prefix, src_asn, dst_asn, path.split())
						print ("time",datetime.datetime.now())
						print ("Withdraw_transaction: Prefix, SRC_ASN, DST_ASN, PATH:", prefix,src_asn,dst_asn, path.split())
						if src_asn not in peer_ids:
							update_peer_ids(src_asn)
						if dst_asn not in peer_ids:
							update_peer_ids(dst_asn)
						tx_info = {'s-as':src_asn, 'd-as':dst_asn, 'prefix': prefix, 'path':path.split()}
						tip1,tip2 = select_tips()
						tx_obj = create_announce_OR_withdraw_transaction(src_asn, tx_type, dag_ledger[tip1].tx_id, dag_ledger[tip2].tx_id, tx_info)
						update_ledger_announce_OR_withdraw(tx_obj)


main()
fp.close()
print ('##################### Info in DAG_LEDGER ###################################')
#for i in dag_ledger.keys():
	#print (i, dag_ledger[i].tx_info)
print (asn2pfx_list,pfx2as)
