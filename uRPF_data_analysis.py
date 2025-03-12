import pickle

def get_asn_types_dict():
    asn_types_dict = dict()
    with open('./three_types_asns.data') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            line = line.strip('\n')
            asn, ty = line.split(',')
            asn_types_dict[asn] = ty
    print('Number of asns: ', len(asn_types_dict))
    
    stub, transit, tier1 = 0, 0, 0
    with open('./urpf_present_asn.res') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            line = line.strip('\n').split(',')
            asn = line[0]
            ty = asn_types_dict.get(asn)
            if ty == 'stub_or_mh_asns': stub = stub + 1
            elif ty == 'etc_asns': transit = transit + 1
            elif ty == 'input_clique_asns': tier1 = tier1 + 1

        print('stub, transit, tier1: ', stub, transit, tier1)
    
    return asn_types_dict
    

def read_uRPF_res():
    
    
    asn_types = get_asn_types_dict()
    
    """
    with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.indirect_vulnerable_urpf.pkl', 'rb') as f:
        indirect_vulnerable_nodes = pickle.load(f)

    print(len(indirect_vulnerable_nodes))
    
    res = defaultdict(set)
    for urpf_asn in indirect_vulnerable_nodes:
    	ty = asn_types[str(urpf_asn)]
    	res[ty].add(urpf_asn)
    
    for ty in res:
    	print(ty, len(res[ty]))
    """
    
    """
    asn_types = get_asn_types_dict()
    x = defaultdict(list)
    with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.as2_set.pkl', 'rb') as f:
        bridging_set = pickle.load(f)
        
        for urpf_asn in bridging_set:
        	ty = asn_types[str(urpf_asn)]
        	if len(bridging_set[urpf_asn]) == 0: print("No bridging networks!")
        	x[ty].append(len(bridging_set[urpf_asn]))
    
    for ty in x:
    	m = statistics.mean(x[ty])
    	
    	print("Mean of bridging networks across different types of networks: ", ty, m)

    y = defaultdict(list)
    with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.as3_set.pkl', 'rb') as f:
        victim_set = pickle.load(f)
        
        for urpf_asn in victim_set:
        	ty = asn_types[str(urpf_asn)]
        	if len(victim_set[urpf_asn]) == 0: print("No victim networks!")
        	y[ty].append(len(victim_set[urpf_asn]))
    
    for ty in y:
    	m = statistics.mean(y[ty])
    	
    	print("Mean of victim networks across different types of networks: ", ty, m)     
    	   	
        	
    z = defaultdict(list)
    with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.as666_set.pkl', 'rb') as f:
        attacker_set = pickle.load(f)
        
        for urpf_asn in attacker_set:
        	ty = asn_types[str(urpf_asn)]
        	if len(attacker_set[urpf_asn]) == 0: print("No attacker networks!")
        	z[ty].append(len(attacker_set[urpf_asn]))
        	
    
    for ty in z:
    	m = statistics.mean(z[ty])
    	
    	print("Mean of attacker networks across different types of networks: ", ty, m)          	
    """           
    
    

    """
    y = []
    with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.as3_set.pkl', 'rb') as f:
        victim_set = pickle.load(f)

        for urpf_asn in victim_set:
                y.append(len(victim_set[urpf_asn]))




    z = []
    with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.as666_set.pkl', 'rb') as f:
        attacker_set = pickle.load(f)

        for urpf_asn in attacker_set:
                z.append(len(attacker_set[urpf_asn])) 
                
    d = defaultdict(list)
    with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.affected_customer_set.pkl', 'rb') as f:
        customer_set = pickle.load(f)

        for urpf_asn in customer_set:
            ty = asn_types[str(urpf_asn)]
            if len(customer_set[urpf_asn]) == 0: print("No customer networks!")
            d[ty].append(len(customer_set[urpf_asn]))
    
    for ty in d:
    	m = statistics.mean(d[ty])
    	maximum = max(d[ty])
    	
    	print("Mean of customer networks across different types of networks: ", ty, m, maximum)
   """

    w = defaultdict(list)
    with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/num_attacks.pkl', 'rb') as f:
        num_attacks = pickle.load(f)

        for urpf_asn in num_attacks:
            ty = asn_types.get(str(urpf_asn))
            if ty == None: continue
            if num_attacks[urpf_asn] == 0: print("No attacks!")
            w[ty].append(num_attacks[urpf_asn])
    
    for ty in w:
    	m = statistics.mean(w[ty])
    	maximum = max(w[ty])
    	
    	print("Mean of customer networks across different types of networks: ", ty, m, maximum)
    
    
    
    with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/tier1_customers.pkl', 'rb') as f:
    	tier1_customers = pickle.load(f)
    	
    w = []
    asn_types = get_asn_types_dict()
    s, x, y, z, n = 0, 0, 0, 0, 0
    with open('/home/zhao/Shujie/Routing_traffic/coding/bgpsimulator/stealthy_hijacks_res/urpf_res/scenario.affected_customer_set.pkl', 'rb') as f:
        customer_set = pickle.load(f)

        for urpf_asn in customer_set:
            
            num = len(customer_set[urpf_asn])
            #if num < 100: continue
            
            s = s + 1
            
            if num == 0:
                
                ty = asn_types[str(urpf_asn)]
                if ty == "stub_or_mh_asns":
                    x = x + 1

            else:
                
                ty = asn_types[str(urpf_asn)]
                if ty == "etc_asns":
                    y = y + 1
                    w.append(len(customer_set[urpf_asn]))
                    if len(customer_set[urpf_asn]) == 59114: print(urpf_asn)
                    if urpf_asn in tier1_customers:
                    	n = n + 1
                    	
                    	
                    	
                    
                    
                elif ty == "'input_clique_asns'":
                    z = z + 1

    print(s, x, y, z, n, max(w))

   

def main():
    read_uRPF_res()
   


if __name__ == "__main__":
    main()
