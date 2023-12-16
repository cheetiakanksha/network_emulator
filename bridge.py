

# BRIDGE ACTING AS A SERVER 
import socket
import sys
import os
import threading
import select
import time
bridge_table={}  
# creating two symbolic links for ip address and port number 
def create_symbolic_link(file_name, data):
    try:
        if os.path.exists(file_name):
            # If it exists, open in append mode and add data
            with open(file_name, 'a') as file:
                file.write(' '.join(data) + '\n')
                #print(f"Data appended to existing file '{file_name}'.")
        else:
            # If it doesn't exist, create a new file and write data
            with open(file_name, 'w') as file:
                file.write(' '.join(data) + '\n')
                #print(f"New file '{file_name}' created and data written.")
        
    except OSError as e:
        print("Error creating symbolic link: {}".format(e))

#ipaddress_link='.lan-name.addr'
#portnum_link='.lan-name.port'
def appending_symboliclinks(bridge):
    try:
        ip,port=bridge.getsockname()
        with open('lan-name.port', 'a+') as file:
            stored_portlan = file.read().splitlines()
            file.truncate(0)
            new_lan_port=[]
            new_lan_ip=[]
            for item in stored_portlan:
                #print(item)
                parts = item.split() 
                #print(parts) # Split the string into parts based on spaces
                name, port_link = parts
                if port_link!=str(port):
                    new_lan_port.append(item)
                    file.write(''.join(item)+'\n')
                    
                else:
                    lanname=str(name)
        #delete that link and note that lan name and also delete the entry in stored_iplan with same lan name
        with open('lan-name.addr', 'a+') as file:
            stored_iplan = file.read().splitlines()
            file.truncate(0)
            for item in stored_iplan:
                parts = item.split() 
                #print(parts) # Split the string into parts based on spaces
                lname, linkip = parts
                
                if lname!=lanname:
                    #delete that link and note that lan name and also delete the entry in stored_iplan with same lan name
                    new_lan_ip.append(item)
                    file.write(''.join(item)+'\n')
        if len(new_lan_ip)==0:
            os.unlink('lan-name.addr')
            os.unlink('lan-name.port')
        print("bridge is closed")
        print("...........")
        bridge.close()
        os._exit(0)
    except KeyboardInterrupt:
        os._exit(0)
    except Exception as e:
        os._exit(0)
        
   
def expired_bridge_table():
    while True:
        current_time=time.time()
        expired_keys=[key for key,value in bridge_table.items() if (current_time-value['timestamp'])>200]
        for key in expired_keys:
            del bridge_table[key]
        time.sleep(60)
        # Check every min

def packet_forwarding(bridge,Srclients,bridge_table,port_assigned,station_name_list):
    try:
        while True:
            read_list,_,_=select.select([bridge]+Srclients,[],[])
            #print(bridge.getpeername())
            ethernet_frame=bridge.recv(2048)
            #print(port)
            if ethernet_frame:
                
                if ethernet_frame=="close":
                    inde=Srclients.index(bridge)
                    print("station/router {} wants to close ".format(station_name_list[inde]))
                    station_name_list.pop(inde)
                    Srclients.pop(inde)
                    print("total connected stations/routers are : {}".format(station_name_list))

                else:
                    port=Srclients.index(bridge)+1
                    ethernet_list_frame=[ethernet_frame]
                    print("{} from {}".format(ethernet_frame,bridge.getpeername()))
                    list_frame=ethernet_list_frame[0]
                    split_values=list_frame.split(',')
                    if len(split_values) >= 4:  # Ensure it has enough elements
                        dest_mac = split_values[0]
                        source_mac = split_values[1]
                    bridge_table[source_mac]={'port':port,'timestamp':time.time()}
                    print(bridge_table)
                    if dest_mac in bridge_table:
                        dest_entry=bridge_table[dest_mac]
                        dest_port=dest_entry['port']
                        ind=dest_port-1
                        socketid=Srclients[ind]
                        socketid.send(ethernet_frame.encode())
                    else:
                        for station in Srclients:
                            if station!=bridge:
                                station.send(ethernet_frame.encode())      
                    bridging_thread=threading.Thread(target=expired_bridge_table)
                    bridging_thread.daemon = True
                    bridging_thread.start()
           
    except KeyboardInterrupt:
        #appending_symboliclinks(bridge)
        for client in Srclients:
            try:
                client.send("closed").encode()
                client.close()
            except socket.error as e:
                pass
        appending_symboliclinks(bridge)
    except Exception as e:
        if Srclients:
            try:
                for client in Srclients:
                    client.send("closed")
                    client.close()
            except socket.error as e:
                pass
        appending_symboliclinks(bridge)

def create_bridge(Lan_name,port_num,Srclients):
    try:
        station_name_list=[]
        port_assigned=0
        bridge = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip_add=socket.gethostbyname("linprog.cs.fsu.edu")
        # binding the socket to the host
        bridge.bind((ip_add, 0))
        port=bridge.getsockname()[1]
        print("enter ctrl+c to terminate")
        #print(ip_address,port)
        print("bridge connected on {} {} .".format(ip_add,port))
        # pass LAN name and number of ports as command line arguments.
        
        a=[Lan_name,ip_add]
        b=[Lan_name,str(port)]
        create_symbolic_link('lan-name.addr', a)
        create_symbolic_link('lan-name.port', b)
        
        #port_num=int(input("number of stations and routers need to be connected"))
        bridge.listen(port_num)
        while port_assigned<=port_num:
            clientsocket,clientadd=bridge.accept()
            station_name=clientsocket.recv(1024)
            if station_name in station_name_list:
                clientsocket.send("reject")
            else:
                print("station {} connected".format(station_name))
                station_name_list.append(station_name)
                print("connected stations are {}".format(station_name_list))
                print("connection established from {}".format(clientadd))
                port_assigned=port_assigned+1
                Srclients.append(clientsocket)
                msg="accept"
                clientsocket.send(msg.encode())
                forwarding_thread = threading.Thread(target=packet_forwarding, args=(clientsocket, Srclients, bridge_table,port_assigned,station_name_list))
                forwarding_thread.start()
                
                #forwarding_thread.join()
                #packet_forwarding(clientsocket,Srclients,bridge_table)
        else:
            msg="reject"
            #clientsocket.recv(1024)
            clientsocket.send(msg.encode())
            
            

    except KeyboardInterrupt:
       print("keyboard interupted")
       station_name_list=[]
       if Srclients:
            try:
                for clients in Srclients:
                    clients.send("closed")
                    clients.close()
            except socket.error as e:
                pass
       appending_symboliclinks(bridge)
       bridge.close()
       sys.exit(0)
    except socket.error as e:
        print("error")
       
            

def main():
    try:
        # sys.argv[1] = 'cs3'
        # sys.argv[2] = '9'
        print("bridge connected")
        Lan_name= sys.argv[1]
        print("lan : {}".format(Lan_name))
        port_num=int(sys.argv[2])
        print("ports : {}".format(port_num))
        if port_num==0:
            print("entered 0 ports")
            os._exit(0)
        else:
            Srclients=[]
            if  os.path.exists('lan-name.addr'):
                exists=False
                try:
                    with open('lan-name.addr', 'r') as file:
                        stored_lan_names = file.read().splitlines()
                        #print(stored_lan_names)
                        names=[]
                        for item in stored_lan_names:
                            #print(item)
                            parts = item.split() 
                            #print(parts) # Split the string into parts based on spaces
                            name, ip = parts
                            names.append(name)
                        #print(names)
                        
                        if Lan_name in names:  # Compare the first part with 'cs1'
                            print("LAN name already exists. Please reenter it.")
                            exists=True
                            os._exit(1)
                        else:
                            exists=False
                            create_bridge(Lan_name,port_num,Srclients)
                        
                    
                except IOError as e :
                    print("error")

            
            else:
                create_bridge(Lan_name,port_num,Srclients)
    except KeyboardInterrupt:
        #appending_symboliclinks()
        os._exit(0)
    except Exception as e:
        print("give proper arguments")
        os._exit(0)
if __name__ == "__main__":
    main()