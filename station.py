


# importing packages
import socket
import sys
import os
import time
import fcntl
import threading
import errno
import ipaddress
import Queue
import select
#Intializing sequence number and arp_cache table
sequence_counter=1
arp_cache_table={}
total_connected_clients=[]# total socket ids for suppose router r1 is connected to cs1 and cs2 it has 2 socket ids
pending_queue = Queue.Queue() # queue to store the packets
#function to load hostnames and ip address storing it in dictianory
def hostnames_data(filename):
    data={}
    try:
        with open(filename,'r') as file:
            for line in file:
                col=line.split()
                if len(col)==2:
                    key, value=col[0],col[1]
                    data[key]=value
    except Exception:
        print("file not found error/unable to load file")
    return(data)

#function to load routing file and store data in dictianory
def routing_data(filename):
    routing_table={}
    try:
        with open("rtables/"+filename,'r') as file:
            for line in file:
                values=line.split()
                dest_add=values[0]
                next_hop_add=values[1]
                network_mask=values[2]
                network_interface=values[3]
                routing_table[dest_add]=(next_hop_add,network_mask,network_interface)
    except Exception:
        print("file not found error/unable to load file")
    return routing_table

#function to load interface file and store data in dictianory
def interfacedata(filename):
    interface_table={}
    try:
        with open("ifaces/"+filename,'r') as file:
            for line in file:
                values=line.split()
                interface=values[0]
                ipadd=values[1]
                network_mask=values[2]
                ethernet_add=values[3]
                interface_connected=values[4]
                interface_table[interface]=(ipadd,network_mask,ethernet_add,interface_connected)
    except Exception:
        print("file not found error/unable to load file")
    return interface_table
# function to find next hop ip address here filename is routing file
def nexthopaddress(filename,destinationadd):
    #obtaining the routing table 
    routing_table=routing_data(filename)
    nexthopipvalues = []
    ip = ipaddress.IPv4Address(unicode(destinationadd))
    for key,value in routing_table.items():
        network_prefix=key+'/'+str(value[1])
        network=ipaddress.IPv4Network(unicode(network_prefix),strict=False)
        if ip in network:
            print("the next hop ip address is {} and the interface is {}".format( key,value[2]))
            nexthopipvalues.append((key,value))
    ele=nexthopipvalues[0][1]
    # if the second colum is 0.0.0.0 then packet is destined on the same lan
    if nexthopipvalues[0][0]=="0.0.0.0":
        lan="same"
    # if the destination ipadd is 0.0.0.0 then it is default router 
    if ele[0]=="0.0.0.0":
        lan="defaultrouter"
    if nexthopipvalues[0][0]!="0.0.0.0" and ele[0]!="0.0.0.0":
        lan="different"
    return nexthopipvalues[0][0],ele[2],lan  

# function to send the packet to the queue
def send_to_queue(frame):
    pending_queue.put(frame)

# function to check whether the received frame is in the queue or not
def check_pending_queue(frame):
    in_queue=False # initially lets assume that frame is not present
    print("checking the recieved arp reply packet in pending queue")
    pending_list=list(pending_queue.queue)
    for packet in pending_list:
        # since each arp request frame and arp reply frame has same sequence number 
        if packet[-1]==frame[-1]:
            in_queue=True
            print("recieved frame is found in the pending queue")
            try:
                # updating the queue since frame is received
                pending_queue.queue.remove(packet)
                print("Frame removed from pending queue")
            except Exception:
                print("Frame not found in pending queue")
    return in_queue

# function to obtain the ip address with respective to station/router name
def deviceaddress(filename,host):
    data=hostnames_data(filename)
    return data[host]

# function to send host name when ipaddress is known
def devicename(filename,add):
    data=hostnames_data(filename)
    for key,value in data.items():
        if value==add:
            host=key
    return host

# function to update the arp cache table entry timeout for every one min it will check 
def expired_arp_cache_table():
    while True:
        if arp_cache_table:
            current_time=time.time()
            #deleting the entries that are expired
            expired_keys=[key for key,value in arp_cache_table.items() if (current_time-value['timestamp'])>300]
            for key in expired_keys:
                del arp_cache_table[key]
            time.sleep(60)
        
# function to route the packets/frames to next hop ip address this is only called in case of routers
def router(clientsocket,socket_id,received_frame,rfile,destination_ip_add):
    next_hop_ip,interface,lan= nexthopaddress(rfile,destination_ip_add)
    #retrieving the socket id using the interface
    socketid=socket_id[interface]
    
    #checks whether it needs forward or not.
    if lan=="same" or lan=="defaultrouter":
        #if socket id of interface is same as the socket id from where the frame is recieved
        if socketid==clientsocket:
            print("no need to forward belongs to same lan")
        else:
            print("forwarding data to {} interface".format(interface))
            socketid.send(received_frame.encode())
    elif lan=="different":
        print("this frame need to be forwaded")
        # interface 
        if socketid!=clientsocket:
            socketid.send(received_frame.encode())

# function to send messages from one station to other station
def send_messages(clientsock,client,hfile,rfile,ifile,src_name,socket_id,total_clients_connected):
    sequence_counter=1
    while True:
        try:
            # enter the message
            inputmsg=raw_input()
            #if input msg is exit or nothing then the station is closed
            if inputmsg=="exit" or inputmsg=="":
                if len(total_clients_connected)>1:
                    for client in total_clients_connected:
                        client.send("close")
                        os._exit(0)
                else:
                    clientsock.send("close")
                    os._exit(0)
            else:
                #enter the destination
                dest_name=raw_input().upper()  
                # while the station name is not same as destionation entered   
                if dest_name!=src_name:
                    #obtain ip address of source and destination using station and destination name
                    destination_ipaddress=deviceaddress(hfile,dest_name)
                    next_hop_ip,interface,lan= nexthopaddress(rfile,destination_ipaddress)
                    # get interface to send the frame
                    clientsock=socket_id[interface]
                    interface_table=interfacedata(ifile)
                    # ip address of the interface
                    source_ipaddress=deviceaddress(hfile,interface)
                    if source_ipaddress!=destination_ipaddress:
                        print("{} wants to send message to {} and the message is {}".format(interface,dest_name,inputmsg))

                        #retrive the source mac address from interface table
                        for items,value in interface_table.items():
                            if items==interface:
                                src_mac_address=value[2]
                        # using destination ip check in arp table whether mac address is present or not.
                        dest_mac_address= arp(destination_ipaddress)
                        #if mac address is not present in arp 
                        if  dest_mac_address==None:
                            # arp request and reply and sending the frame to queue
                            print("ip address not exits in arp cache ")
                            type=0
                            op=0#arp request
                            dest_mac_address='FF:FF:FF:FF:FF:FF'#intialize destination mac address
                            ethernet_frame=[dest_mac_address,src_mac_address,type,op,source_ipaddress,src_mac_address,destination_ipaddress,dest_mac_address,inputmsg,sequence_counter]
                            print("sending arp request {} ".format(ethernet_frame))
                            ethernet_frame_str = ','.join(map(str, ethernet_frame))
                            clientsock.send(ethernet_frame_str.encode())
                            #sending it queue
                            send_to_queue(ethernet_frame_str)
                            # updating the sequence number
                            sequence_counter=sequence_counter+1
                        # if mac address exists in  arp cache   
                        else:
                            type=1
                            print("destination mac address exists in arp cache packet sent")
                            ethernet_frame=[dest_mac_address,src_mac_address,type,destination_ipaddress,source_ipaddress,inputmsg,sequence_counter]
                            ethernet_frame_str = ','.join(map(str, ethernet_frame))
                            print("sending ip frame :{}".format(ethernet_frame_str))
                            clientsock.send(ethernet_frame_str.encode())
                            sequence_counter=sequence_counter+1
                    else:
                        print("you are trying to send to yourself")
                        continue
                else:
                    #if src name and destiname are same 
                    print("you are trying to send message to yourserlf")
                    continue
        except KeyboardInterrupt:
            print("keyboard interrupt")
            clientsock.send("close")
            clientsock.close()
            os._exit(0)
        except socket.error as e:
            print("keyboard interrupt")
            clientsock.send("close")
            clientsock.close()
            os._exit(0)
                    
# function to receieve messages
def receieve_messages(totalclients,client,hfile,rfile,ifile,name,socket_id):
    #need to check whether it is ethernet ip frame or arp packet 
    while True:
        try:
            #receiving frames
            read_sockets, _, _ = select.select(totalclients, [], []) 
            for clientsock in read_sockets:
                received_frame=clientsock.recv(2048).decode()
                if received_frame=='closed' or received_frame == '' or received_frame=='reject':
                    print("bridge closed")
                    clientsock.close()
                    os._exit(0)
                    break
                else:
                    print("{} recieved from {}".format(received_frame,clientsock.getpeername()))
                    received_frame=received_frame.encode('ascii','ignore').split(',')
                    for name, c in socket_id.items():
                        if c == clientsock:
                            src_name=name
                    if len(received_frame) >= 4:  # Ensure it has enough elements
                        destination_mac_address = received_frame[0]
                        source_mac_address = received_frame[1]
                        type=int(received_frame[2])
                        #ip packet is recieved
                        if type==1:
                            destination_ip_add=received_frame[3]
                            source_ip_add=received_frame[4]
                            destination=devicename(hfile,source_ip_add)
                            recieved_msg=received_frame[5]
                            source_ipaddress=deviceaddress(hfile,src_name)
                            #if the ip address matches (the frame belongs to that station)
                            if source_ipaddress==destination_ip_add:
                                print("message recieved from {} ".format(destination))
                                print("\n...................Message...................\n")
                                print("destinatio mac address : {}".format(destination_mac_address))
                                print("source mac address : {}".format(source_mac_address))
                                print("type: {}".format(type))
                                print("source ip address: {}".format(source_ip_add))
                                print("destination ip address: {}".format(destination_ip_add))
                                print("message: {}".format(recieved_msg))
                            else:
                                if client=="station":
                                    print("Message  is discarded")
                                else:
                                    # frame need to be forwaded
                                    received_frame = ','.join(map(str, received_frame))
                                    router(clientsock,socket_id,received_frame,rfile,destination_ip_add)
                                    
                        # arp frame
                        elif type==0:
                            destip=received_frame[6]
                            if client=="router":
                                received_frame = ','.join(map(str, received_frame))
                                router(clientsock,socket_id,received_frame,rfile,destip)
                            else:
                                source_ipaddress=deviceaddress(hfile,src_name)
                                print("arp frame is received checking whether it is arp request or arp reply")
                                op=int(received_frame[3])
                                if op==0:
                                    print("arp request is received")
                                    #it is arp request is received
                                    op=1
                                    source_ip_add=received_frame[4]
                                    destip=received_frame[6]
                                    if source_ipaddress==destip:
                                        print("the ip addresses matches/ sending arp reply")
                                        interface_table=interfacedata(ifile)
                                        for value in interface_table.values():
                                            if value[0] == destip:
                                                destination_mac_address= value[2]
                                        seq=received_frame[9]
                                        print("\n................. sending arp reply :..............\n")
                                        print("destinatio mac address : {}".format(source_mac_address))
                                        print("source mac address : {}".format(destination_mac_address))
                                        print("type: {}".format(type))
                                        print("op: {}".format(op))
                                        print("source ip address: {}".format(destip))
                                        print("destination ip address: {}".format(source_ip_add))
                                        print("message: {}".format(received_frame[8]))
                                        ethernet_frame=[source_mac_address,destination_mac_address,type,op,destip,destination_mac_address,source_ip_add,source_mac_address,received_frame[8],seq]
                                        ethernet_frame_str = ','.join(map(str, ethernet_frame))
                                        clientsock.send(ethernet_frame_str.encode())
                                    else:
                                        print("Request is ignored ")
                                elif op==1:
                                    #it is arp reply is recieved
                                    print("reply frame is received")
                                    #checking whether it is queue
                                    check_pending_queue(received_frame)
                                    macaddr_destination=received_frame[7]
                                    source_ip_add=received_frame[4]
                                    # check in the queue and send the message
                                    dest_ip=received_frame[6]
                                    #updating arp cache table
                                    arp_cache_table[source_ip_add]={'mac_address':source_mac_address,'timestamp':time.time()}
                                    type=1
                                    ethernet_frame=[source_mac_address,macaddr_destination,type,source_ip_add,dest_ip,received_frame[8]]#received_frame should be obtained from queue packet
                                    ethernet_frame_str = ','.join(map(str, ethernet_frame))
                                    print(" \n................FRAME SENT WITH IP PACKET.............\n")
                                    print("sending ethernet frame(ip frame), the frame is:")
                                    print("destinatio mac address : {}".format(source_mac_address))
                                    print("source mac address : {}".format(macaddr_destination))
                                    print("type: {}".format(type))
                                    print("destination ip address: {}".format(source_ip_add))
                                    print("source ip address: {}".format(dest_ip))
                                    print("message: {}".format(received_frame[8]))
                                    clientsock.send(ethernet_frame_str.encode())
                                    
                                else:
                                    print("not ip frame nor arp frame ")
                    else:
                        print("invalid frame")
        except KeyboardInterrupt:
            print("keybopard interupt")
            clientsock.send("close")
            clientsock.close()
            os._exit(0)
        except socket.error as e:
            print("keyboard interrupt")
            clientsock.send("close")
            clientsock.close()
            os._exit(0)
        except Exception:
            os._exit(0)


# function to check mac address in arp cahe table 
def arp(ipaddress):
    value=None
    #arp_cache_table=expired_arp_cache_table()
    print("...........arp cache table..........")
    print(arp_cache_table)
    if arp_cache_table:
        print("arp cache:")
        print(arp_cache_table)
        for key in arp_cache_table: 
            if key == ipaddress:
                value=arp_cache_table[key]
        if value:
            return value['mac_address']
        else:
            return None
    else:
        print("arp cache table is empty ")
        return value 

def try_connecting(ip_add,port_num,client,hfile,rfile,ifile,src_name,socket_id,ip_values):
    num_of_attempts=5
    time_to_retry=2
    client_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    old_socket_flags = 0

    try: 
        port_num = int(port_num)
        client_socket.connect((ip_add, port_num))
        client_socket.send(src_name)
        message=client_socket.recv(1024).decode()
        sender_address = client_socket.getpeername()
        print("{} recieved from {}".format(message,sender_address))
        print("enter ctrl+c and enter to exit/ type exit ")
        
        if message=="accept":
            total_connected_clients.append(client_socket)
            socket_id[src_name]=client_socket   
        else:
            for attempt in range(num_of_attempts):
                try:
                    message=client_socket.recv()
                except Exception as e:
                    print("Connection attempt {} failed. Retrying in {} seconds...".format(attempt + 1, time_to_retry))
                    time.sleep(time_to_retry)
                    os._exit(0)
            
        if len(total_connected_clients)==len(ip_values):
            send_thread=threading.Thread(target=send_messages,args=(client_socket,client,hfile,rfile,ifile,src_name,socket_id,total_connected_clients))
            receive_thread=threading.Thread(target=receieve_messages,args=(total_connected_clients,client,hfile,rfile,ifile,src_name,socket_id))
            cleanup_thread = threading.Thread(target=expired_arp_cache_table)
            cleanup_thread.daemon = True
            send_thread.start()
            receive_thread.start()
            cleanup_thread.start()  
    except KeyboardInterrupt:
          print("error") 
    except socket.error:
        for attempt in range(num_of_attempts):
            try:
                message=client_socket.recv()
            except Exception as e:
                print("Connection attempt {} failed. Retrying in {} seconds...".format(attempt + 1, time_to_retry))
                time.sleep(time_to_retry)
        print(" reject")
    
    

def main():
    try:
        if sys.argv[1]=='-no':
                client="station"
                print("{} is connected".format(client))
        else:
            client="router"
            print("{} is connected".format(client))
        # taking arguments
        hostname_file=sys.argv[4]
        router_file=sys.argv[3]
        interface_file=sys.argv[2]
        hosts_table=hostnames_data(hostname_file)
        interface_table=interfacedata(interface_file)
        print("loading interface file {}, router file {} ,hostname file {}".format(interface_file,router_file,hostname_file))
        ip_values=[]
        port_values=[]
        if '.' in router_file:
            letter_after_dot = router_file.split('.')[1]  # Getting the first character after the dot
        src_name=letter_after_dot.upper()
        last_column_values = [value[3] for value in interface_table.values()]
        # filling ip and port values in the file
        try:
            with open('lan-name.addr', 'r') as file:
                real_ip = file.read().splitlines()
                for x in last_column_values:
                    for item in real_ip:
                        lan,ip=item.split()
                        if lan==x:
                            connected_lan=lan
                            ip_values.append(ip)
            with open('lan-name.port', 'r') as file:
                real_ports = file.read().splitlines()
                for y in last_column_values:
                    for item in real_ports:
                        lan,port=item.split()
                        if lan==y:
                            port_values.append(port)
            station_socket=[]
            socket_id={}
            #station or router
            if client=="station":
                if len(ip_values)>1:
                    src_name_lan=src_name+last_column_values[0]
                    try_connecting(ip_values[0],port_values[0],client,hostname_file,router_file,interface_file,src_name_lan,socket_id,ip_values)
                    src_name_lan=src_name+last_column_values[1]
                    try_connecting(ip_values[1],port_values[1],client,hostname_file,router_file,interface_file,src_name_lan,socket_id,ip_values)
                else:
                    if len(interface_table)>1:
                        src_name_lan=src_name+connected_lan
                        connect_thread=threading.Thread(target=try_connecting,args=(ip_values[0],port_values[0],client,hostname_file,router_file,interface_file,src_name_lan,socket_id,ip_values))
                        connect_thread.start()
                        connect_thread.join()
                    else:
                        connect_thread=threading.Thread(target=try_connecting,args=(ip_values[0],port_values[0],client,hostname_file,router_file,interface_file,src_name,socket_id,ip_values))
                        connect_thread.start()
                        connect_thread.join()
            else:
                client=="router"      
                if len(ip_values)>1:
                    src_name_lan=src_name+'-'+last_column_values[0]
                    try_connecting(ip_values[0],port_values[0],client,hostname_file,router_file,interface_file,src_name_lan,socket_id,ip_values)
                    src_name_lan=src_name+'-'+last_column_values[1]
                    try_connecting(ip_values[1],port_values[1],client,hostname_file,router_file,interface_file,src_name_lan,socket_id,ip_values)
                    
                else:
                    connect_thread=threading.Thread(target=try_connecting,args=(ip_values[0],port_values[0],client,hostname_file,router_file,interface_file,src_name,socket_id,ip_values))
                    connect_thread.start()
                    connect_thread.join()
                    
        except (OSError, IOError) as e:
            print("Error reading the symbolic link: {}".format(e))
        except KeyboardInterrupt:
            print("keyboard interrupt")   
    except Exception:
        print("pass proper arguments")     

if __name__=="__main__":
    main()
