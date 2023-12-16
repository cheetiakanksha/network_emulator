
PROJECT:NETWORK EMULATOR
Topology:

 A------------             D
 |            |            |
cs1----R1----cs2----R2----cs3
 |            |
 B            C

Compilation: it can complied in python 2 compiler
run the following commands in each terminal 
    1.python bridge.py cs1 8
    2.python bridge.py cs2 8
    3.python bridge.py cs3 8
    4.python station.py -route ifaces.r1 rtable.r1 hosts
    5.python station.py -route ifaces.r2 rtable.r2 hosts
    6.python station.py -no ifaces.a rtable.a hosts
    7.python station.py -no ifaces.b rtable.b hosts
    8.python station.py -no ifaces.c rtable.c hosts
    9.python station.py -no ifaces.d rtable.d hosts

    
Testing Cases:
    case 1: to close the bridge
    -> after starting all the stations, routers and bridges just enter ctrl+c and enter. 
    automically all the respective bridges are closed
    case 2: to close any of the station or router 
    -> enter ctrl+c and enter in any of the station.the disconnected station is updated in bridge.
    case 3: running the bridge with same name 
    -> to test this run the bridge program with already existed name
    case 4: real ip and port values
    -> real ip values and port values are updated in lan-name.addr and lan-name.port files respectively.
    -> we only created one file for ip value and one file for port value .
    -> every time bridge is runned the ip and port are updated in the same file 
    -> if bridges / station/ router terminal is deleted then the lan-name.addr and lan-name.port 
    are deleted manually otherwise they are deleted automically.
    case 5: sending and recieving messages
    -> when terminal is started enter the message and destination to send.
    case 6: arp cache table, bridge table
    -> these two table are displayed while running the program

