#import matplotlib.pyplot as plt
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
from datetime import datetime, timedelta
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

dag_ledger = {}

asn_prefix_state = {} ### {asn:  {prefix: {'type':'received/allocated', 'tx_id':'asdfd' }}}
RIR_prefix_state = {} ### {prefix: {src_asn:100/RIR, dst_asn:200, tx_id:'asdfsd'}}

RIR_Provider = {} ### RIR to provider - prefixes, start date, end date
RIR_P_C = {} ### RIR { provider: {cust1:{prefix details}, cust2: {prefix details}}}

genesis_tx_ids = []


result=  'fsdi.csv'
fp = open(result, 'a')

class tx(): # 
    def __init__(self, tx_id, tx_type, address, tip1_tx_id, tip2_tx_id, ref_tx_id, tx_info, time_stamp, nonce, signature):
        self.tx_id = tx_id
        self.tx_type = tx_type
        self.address = address ## public key (ethereum address) of the tx creator
        self.tip1_tx_id = tip1_tx_id
        self.tip2_tx_id = tip2_tx_id
        self.ref_tx_id = ref_tx_id
        self.tx_info = tx_info
        self.time_stamp = time_stamp
        self.signature = signature
        self.nonce = nonce
        #self.pw = pw

#### msg and secret key of the corresponding AS/node to sign- return signature #######################

def sign(encoded_msg,sk): 
    #encoded_msg = msg.encode()
    message_hash = defunct_hash_message(encoded_msg)
    eth_account_privatekey = HexBytes(sk.to_hex())      ######### convert to hex
    signed_message = w3.eth.account.signHash(message_hash,private_key=eth_account_privatekey)
    signature = bytes(signed_message.signature)
    return signature
#####################################################################################################

#### verify signature - passing signature and ethereum account address of the AS/node ###############

def verify_signature(signature, message_hash, address):
	retrieved_eth_address = w3.eth.account.recoverHash(message_hash, signature= HexBytes(signature))
	#print ("retrieved_eth_address",retrieved_eth_address)
	if retrieved_eth_address == address:
		return True
	else:
		return False

#######################return tx_obj ########################################################################

################## return nonce and hash associated with the data ##############################################
def find_nonce(data): 
	found = 0
	nonce = 0
	while found == 0:
		z = data+str(nonce)
		hh = hashlib.sha256(z.encode()).hexdigest()
		#print (hh)
		if hh[:4] == '0000':
			found = 1
			break
		nonce +=1
	return nonce, hh
#########################################################################################################
def create_revoke_OR_update_transaction(asn, tx_type, tip1_tx_id, tip2_tx_id, ref_tx_id, tx_info):

	time_stamp = time.time()	
	tx_id_msg = str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(ref_tx_id)+str(tx_info)+str(time_stamp)
	tx_id = hashlib.sha256(tx_id_msg.encode()).hexdigest()
	#print ('tx_id',tx_id)
	msg = str(tx_id)+str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(ref_tx_id)+str(tx_info)+str(time_stamp)
	#print ("nonce_msg in create transaction",msg)
	(nonce,h) = find_nonce(msg)
	#print ("hash,nonce of transaction", h, nonce) 
	final_msg = msg+str(nonce)
	encoded_msg = final_msg.encode()
	
	tx_signature = {} ## dict to hold multiple signatures
	src_asn = tx_info['s-as']
	dst_asn = tx_info['d-as']

	sk_src_asn = peer_ids[src_asn]['sk']
	signature_src_asn = sign(encoded_msg, sk_src_asn) ## signature using private key of src asn

	sk_dst_asn = peer_ids[dst_asn]['sk']
	signature_dst_asn = sign(encoded_msg, sk_dst_asn) ## signature using private key of dst asn

	tx_signature[src_asn] = signature_src_asn
	tx_signature[dst_asn] = signature_dst_asn

	tx_obj = tx(tx_id, tx_type, peer_ids[asn]['address'], tip1_tx_id, tip2_tx_id, ref_tx_id, tx_info, time_stamp, nonce, tx_signature)
	return tx_obj
    

    ################################################################################################################

def create_transaction(asn, tx_type, tip1_tx_id, tip2_tx_id, ref_tx_id, tx_info):

	time_stamp = time.time()	
	tx_id_msg = str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(ref_tx_id)+str(tx_info)+str(time_stamp)
	tx_id = hashlib.sha256(tx_id_msg.encode()).hexdigest()
	#print ('tx_id',tx_id)
	msg = str(tx_id)+str(tx_type)+str(tip1_tx_id)+str(tip2_tx_id)+str(ref_tx_id)+str(tx_info)+str(time_stamp)
	#print ("nonce_msg in create transaction",msg)
	(nonce,h) = find_nonce(msg)
	#print ("hash,nonce of transaction", h, nonce) 
	final_msg = msg+str(nonce)
	encoded_msg = final_msg.encode()
	
	tx_signature = {} ## dict to hold multiple signatures
	double_spend = False


	sk = peer_ids[asn]['sk']
	signature = sign(encoded_msg, sk) ## signature using private key of asn

	if asn == ir_asn:
		tx_signature[asn] = signature
	else:
		tx_signature[asn] = signature ## signature of asn
		## verify double spending (by RIR) and sign ####
		pfx_in_tx = ipaddress.ip_network(tx_info['prefix'])
		already_allocated = False
		#print ("RIR_P_C",RIR_P_C)
		#if len(RIR_P_C) != 0:
		if (asn in RIR_P_C):
			for i in RIR_P_C[asn]:
				pfx_customer = ipaddress.ip_network(RIR_P_C[asn][i]['prefix'])
				if pfx_in_tx.overlaps(pfx_customer):
					already_allocated =  True
	########### add rir signature to the transaction ################################		
		if (not already_allocated):
			sk_rir = peer_ids[ir_asn]['sk']
			signature_rir = sign(encoded_msg, sk_rir) ## signature using private key of asn
			tx_signature[ir_asn] = signature_rir
		else:
			double_spend = True
			print ("Transaction cannot be creted due to duplicate allocation (double spending)")
    ##################################################################################
	# 	sk_rir = peer_ids[ir_asn]['sk']
	# 	signature_rir = sign(encoded_msg,sk_rir)

	#########################  creating a tx_obj from the values of tx #####################################
	if (not double_spend):
		tx_obj = tx(tx_id, tx_type, peer_ids[asn]['address'], tip1_tx_id, tip2_tx_id, ref_tx_id, tx_info, time_stamp, nonce, tx_signature)
		return tx_obj
	else:
		return None
	#return tx_obj
    ################################################################################################################

    ############## udpate ledger after verifying Nonce, PoA and Hisory ###########################################################
def update_ledger_revoke_OR_update(tx_obj):
	################################# verifying nonce ###############################################################
	msg = str(tx_obj.tx_id)+str(tx_obj.tx_type)+str(tx_obj.tip1_tx_id)+str(tx_obj.tip2_tx_id)+str(tx_obj.ref_tx_id)+str(tx_obj.tx_info)+str(tx_obj.time_stamp)
	#print ("in update ledger nonce_msg,nonce",msg,tx_obj.nonce)
	nonce_msg = msg+str(tx_obj.nonce)
	hash_with_nonce_msg = hashlib.sha256(nonce_msg.encode()).hexdigest()
	#print ("hash_with_nonce_msg", hash_with_nonce_msg)
	if hash_with_nonce_msg[:4] == '0000':
		print ("######################### Nonce verified#########################################")
		tx_msg = str(tx_obj.tx_id)+str(tx_obj.tx_type)+str(tx_obj.tip1_tx_id)+str(tx_obj.tip2_tx_id)+str(tx_obj.ref_tx_id)+str(tx_obj.tx_info)+str(tx_obj.time_stamp)+str(tx_obj.nonce)
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
				print ("##################### SIGNATURE VERIFIED ######################")
		if PoA:
			#print ("in history verification")
			ref_tx_id = tx_obj.ref_tx_id
			ref_tx_obj = dag_ledger[ref_tx_id]
			if ((ref_tx_obj.tx_info['prefix'] == tx_obj.tx_info['prefix']) and (ref_tx_obj.tx_info['s-as'] == tx_obj.tx_info['s-as'])):
				print ("################ HISTORY VERIFIED (Ledger) ##################################################")
				dag_ledger[tx_obj.tx_id] = tx_obj

    ############## udpate ledger after verifying Nonce, PoA and Hisory ###########################################################
def update_ledger(tx_obj):
	################################# verifying nonce ###############################################################
	msg = str(tx_obj.tx_id)+str(tx_obj.tx_type)+str(tx_obj.tip1_tx_id)+str(tx_obj.tip2_tx_id)+str(tx_obj.ref_tx_id)+str(tx_obj.tx_info)+str(tx_obj.time_stamp)
	#print ("in update ledger nonce_msg,nonce",msg,tx_obj.nonce)
	nonce_msg = msg+str(tx_obj.nonce)
	hash_with_nonce_msg = hashlib.sha256(nonce_msg.encode()).hexdigest()
	#print ("hash_with_nonce_msg", hash_with_nonce_msg)
	if hash_with_nonce_msg[:4] == '0000':
		print ("######################### Nonce verified#########################################")
		tx_msg = str(tx_obj.tx_id)+str(tx_obj.tx_type)+str(tx_obj.tip1_tx_id)+str(tx_obj.tip2_tx_id)+str(tx_obj.ref_tx_id)+str(tx_obj.tx_info)+str(tx_obj.time_stamp)+str(tx_obj.nonce)
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
				print ("##################### SIGNATURE VERIFIED ######################")
		if PoA:
			print ("in history verification")
			ref_tx_id = tx_obj.ref_tx_id
			#print (dag_ledger, ref_tx_id)
			ref_tx_obj = dag_ledger[ref_tx_id]
			if ref_tx_id in genesis_tx_ids:
				print ("################ HISTORY VERIFIED (Genesis) ##################################################")
				dag_ledger[tx_obj.tx_id] = tx_obj
			else:
				pfx1 = ipaddress.ip_network(ref_tx_obj.tx_info['prefix'])
				pfx2 = ipaddress.ip_network(tx_obj.tx_info['prefix'])
				#print (pfx1,pfx2)
				if (pfx1.overlaps(pfx2) and ref_tx_obj.tx_info['d-as'] == tx_obj.tx_info['s-as']):
					print ("################ HISTORY VERIFIED (Ledger) ##################################################")
					dag_ledger[tx_obj.tx_id] = tx_obj

############## udpate ledger after verifying PoA ###########################################################
def update_ledger_genesis(tx_obj,value):
	############# verify if ref_tx_id is in ledger  ####################################################
	msg = str(tx_obj.tx_id)+str(tx_obj.tx_type)+str(tx_obj.tip1_tx_id)+str(tx_obj.tip2_tx_id)+str(tx_obj.ref_tx_id)+str(tx_obj.tx_info)+str(tx_obj.time_stamp)
	#print ("in update ledger nonce_msg,nonce",msg,tx_obj.nonce)
	#(nonce,h) =  find_nonce(msg)
	#print ("in update ledger hash,nonce", nonce,h)
	#nonce = tx_obj.nonce
	#print ('nonce',nonce)
	nonce_msg = msg+str(tx_obj.nonce)
	hash_with_nonce_msg = hashlib.sha256(nonce_msg.encode()).hexdigest()
	#print ("hash_with_nonce_msg", hash_with_nonce_msg)
	if hash_with_nonce_msg[:4] == '0000':
		print ("############### (genesis) nonce verified ############################# ")
		tx_msg = str(tx_obj.tx_id)+str(tx_obj.tx_type)+str(tx_obj.tip1_tx_id)+str(tx_obj.tip2_tx_id)+str(tx_obj.ref_tx_id)+str(tx_obj.tx_info)+str(tx_obj.time_stamp)+str(tx_obj.nonce)
		encoded_tx_msg = tx_msg.encode()
		tx_message_hash = defunct_hash_message(encoded_tx_msg)
		#print ('tx_obj.signature, tx_message_hash, tx_obj.address',tx_obj.signature, tx_message_hash, tx_obj.address)
		print(tx_obj.tx_info)
		#print ('tx_obj.tx_info[src_asn]', asn)
		PoA = True
		for i in tx_obj.signature:
			signature  = tx_obj.signature[i]
			if(not verify_signature(signature, tx_message_hash, tx_obj.address)):
				PoA = False
			else:
				print ("##################### (genesis) signature verified ######################")
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
	tx_obj = create_transaction(ir_asn,'','','','','{genesis:0}')
	update_ledger_genesis(tx_obj,value=0)
	genesis_tx_ids.append(tx_obj.tx_id)
	#print ("dag_ledger['genesis0'].tx_id, dag_ledger['genesis0'].address,dag_ledger['genesis0'].tx_info)", dag_ledger['genesis0'].tx_id, dag_ledger['genesis0'].address,dag_ledger['genesis0'].tx_info)
	tx_obj = create_transaction(ir_asn,'','','','','{genesis:1}')
	update_ledger_genesis(tx_obj,value=1)
	genesis_tx_ids.append(tx_obj.tx_id)
	#print (dag_ledger['genesis1'].tx_id, dag_ledger['genesis1'].address,dag_ledger['genesis1'].tx_info)
	#print ('length of dag_ledger', len(dag_ledger))
		############# creating transactions from dataset #########################################################
	with open('/home/sivsai/Documents/prashanth/prefix_dataset-100.csv', 'r') as f:
		reader = csv.reader(f, dialect='excel', delimiter=',')
		for row in reader:
			if row:
				#print (row[0],row)
				if (row[0] == 'assign'):
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
						#ref_tx_id =  dag_ledger['genesis0'].tx_id
						ref_tx_id = random.sample(genesis_tx_ids,1)[0]
						tx_obj = create_transaction(src_asn, tx_type, dag_ledger[tip1].tx_id, dag_ledger[tip2].tx_id, ref_tx_id, tx_info)
						#print (tx_obj.tx_info)
						update_ledger(tx_obj)
						updated_tx_info = tx_obj.tx_info 
						#print ("updated_tx_info", updated_tx_info['start_time'], updated_tx_info['end_time'])
						#{asn:  {prefix: {'type':'received/allocated', 'tx_id':'asdfd' }}}
						if dst_asn in asn_prefix_state:
							asn_prefix_state[dst_asn][prefix] = {'type':'received','ref_tx_id': tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}
						else:
							asn_prefix_state[dst_asn] = {prefix:{'type':'received','ref_tx_id': tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}}

					
						if dst_asn in RIR_Provider:
							RIR_Provider[dst_asn][prefix] = {'ref_tx_id':tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}
						else:
							RIR_Provider[dst_asn] = {prefix:{'ref_tx_id':tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}}

						# if dst_asn in RIR_prefix_state:
						# 	RIR_prefix_state[dst_asn] = {}

						RIR_prefix_state[prefix] =  {'sr_asn':ir_asn, 'dst_asn': dst_asn, 'ref_tx_id':tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}
					else: ####### RIR signature is required for allocating prefixes in transactions ################
						for i in list(asn_prefix_state[src_asn].keys()):
							src_pfx = ipaddress.ip_network(i)
							dst_pfx = ipaddress.ip_network(prefix)
							if (dst_pfx.overlaps(src_pfx)):
								ref_tx_id = asn_prefix_state[src_asn][str(src_pfx)]['ref_tx_id']
								print ("ref_tx_id",ref_tx_id)
								break
						tx_obj = create_transaction(src_asn, tx_type, dag_ledger[tip1].tx_id, dag_ledger[tip2].tx_id, ref_tx_id, tx_info)
						#print (tx_obj.tx_info)
						if (tx_obj):
							update_ledger(tx_obj)
							updated_tx_info = tx_obj.tx_info
							#print ("updated_tx_info", updated_tx_info['start_time'], updated_tx_info['end_time'])
							#print ('src_pfx,dst_pfx', src_pfx, dst_pfx)
							if src_asn in asn_prefix_state:
								asn_prefix_state[src_asn][prefix] = {'type':'allocated', 'ref_tx_id': tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}
							else:
								asn_prefix_state[src_asn] = {prefix:{'type':'allocated','ref_tx_id': tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}}

							if dst_asn in asn_prefix_state:
								asn_prefix_state[dst_asn][prefix] = {'type':'received', 'ref_tx_id': tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}
							else:
								asn_prefix_state[dst_asn] = {prefix:{'type':'received','ref_tx_id': tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}}
							RIR_prefix_state[prefix] =  {'sr_asn':src_asn, 'dst_asn': dst_asn, 'ref_tx_id':tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}
							#print ("find reference tx_id")

							if src_asn in RIR_P_C:
								RIR_P_C[src_asn][dst_asn] = {'prefix':prefix,'ref_tx_id':tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}
							else:
								RIR_P_C[src_asn] = {dst_asn: {'prefix':prefix,'ref_tx_id':tx_obj.tx_id, 'start_time':updated_tx_info['start_time'], 'end_time':updated_tx_info['end_time']}}
						else:
							print ('double spending transaction')
							continue

				if (row[0] == 'revoke'):
					print ("revoke_transaction", row)
					tx_type = row[0]
					src_asn =  int(row[1])
					prefix = row[2]
					dst_asn = int(row[3])
					tx_info = {'s-as':src_asn, 'd-as':dst_asn, 'prefix': prefix}
					tip1,tip2 = select_tips()
					ref_tx_id =  asn_prefix_state[src_asn][str(prefix)]['ref_tx_id']
					print ('ref_tx_id',ref_tx_id)
					tx_obj = create_revoke_OR_update_transaction(src_asn, tx_type, dag_ledger[tip1].tx_id, dag_ledger[tip2].tx_id, ref_tx_id, tx_info)
					update_ledger_revoke_OR_update(tx_obj)
					#print ('asn_prefix_state before removing', asn_prefix_state)
					#print ('RIR_P_C before removing', RIR_P_C)
					######## remove prefix allocation from RIR_P_C and asn_prefix_state #############
					del asn_prefix_state[src_asn][prefix]
					del asn_prefix_state[dst_asn]
					del RIR_P_C[src_asn][dst_asn]
					#print ('asn_prefix_state after removing', asn_prefix_state)
					#print ('RIR_P_C after removing', RIR_P_C)

				if (row[0] == 'update'):
					print ("update_transaction", row)
					tx_type = row[0]
					src_asn =  int(row[1])
					prefix = row[2]
					dst_asn = int(row[3])
					end_time = row[4] 
					tx_info = {'s-as':src_asn, 'd-as':dst_asn, 'prefix': prefix, 'end_time':end_time}
					tip1,tip2 = select_tips()
					ref_tx_id =  asn_prefix_state[dst_asn][str(prefix)]['ref_tx_id']
					print ('ref_tx_id',ref_tx_id)
					tx_obj = create_revoke_OR_update_transaction(src_asn, tx_type, dag_ledger[tip1].tx_id, dag_ledger[tip2].tx_id, ref_tx_id, tx_info)
					update_ledger_revoke_OR_update(tx_obj)
					
					######## update time in RIR_P_C and asn_prefix_state #############
					asn_prefix_state[src_asn][prefix]['end_time'] = end_time
					asn_prefix_state[dst_asn][prefix]['end_time'] = end_time
					#print (RIR_P_C)
					RIR_P_C[src_asn][dst_asn]['end_time'] = end_time

main()
fp.close()
print ('##################### Info in DAG_LEDGER ###################################')
for i in dag_ledger.keys():
	print (dag_ledger[i].tx_info)
# print ('dag_ledger', dag_ledger.keys())
# print ('peer_ids',peer_ids)
# print ('asn_prefix_state',asn_prefix_state)
#print ('rir_prefix_state',RIR_prefix_state)
#print (RIR_Provider)
#print (RIR_P_C)       
