import socket
import sys
import server
import os
from hashlib import sha1
from uuid import uuid4
import pickle
import random
import tools

HOST = '127.0.0.1'
PORT = 3344

user_ip = ""
user_hash = ""
user_data = ""


def create_id():
    random_string = str(uuid4())
    print("Random string for hash ", random_string)
    user_hash = tools.create_hash(random_string)
    print("Your id: " + user_hash)
    return user_hash


def get():
    shuffled_dht = list(tools.dht)
    shuffled_dht.pop(0)
    random.shuffle(shuffled_dht)
    # We need to shuffle the dht to distribute network load between nodes
    for node in shuffled_dht:
        address = node.split('-')[1]
        host = str(address.split(':')[0])
        port = int(address.split(':')[1])
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                s.sendall(str.encode('get' + ':' + user_data))
                data = s.recv(4096)
                unpacked = pickle.loads(data)
                with open(tools.dht_path, 'r') as f:
                    read = f.readlines()
                    first = read[0]
                    read.pop(0)
                    read.extend(unpacked)
                with open(tools.dht_path, 'w') as f:
                    print(list(set(read)))
                    append_list = list(set(read))
                    append_list.remove(first)
                    append_list.insert(0, first)
                    f.writelines(append_list)
                with open(tools.dht_path, 'r') as f:
                    new_dht = f.readlines()
                tools.dht = new_dht
            break
        except Exception as ex:
            print(str(ex))
            continue


def put(similarities, command):
    print("Sort_similarities: " + str(similarities))

    for sim in similarities:
        print(str(sim))
        node_ip = sim.split(':')[0]
        node_port = sim.split(':')[1]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((node_ip, int(node_port)))
                s.sendall(str.encode(command))
                recvdata = s.recv(4096)
                nodes = list(pickle.loads(recvdata))

                if ':' in str(nodes):  # If we received '127.0.0.1:4444' for example
                    for node in nodes:
                        # Here we're removing our ip from list and if we have
                        # the same node in the sorted similarities list, we need
                        # to remove it from the received list too.
                        if user_ip in str(node):
                            nodes.remove(node)
                        elif str(node) in str(similarities):
                            nodes.remove(node)

                    if len(nodes) == 1 and nodes[0] in str(similarities):
                        # This fixes a bug when 'for' loop in the lines above can't remove the last element
                        nodes.clear()
                    elif len(nodes) != 0:  # If received list contains at least one element
                        similarities.extend(nodes)

                else:  # elif '[OK]' not in str(nodes) - draft
                    print("File found! " + filename + " is:\n" + str(pickle.loads(recvdata)))
        except Exception as ex:
            print('Exception: ' + str(ex))
            pass


if len(sys.argv) == 3 and not os.path.isfile(sys.argv[2]):
    PORT = sys.argv[1]
    tools.dht_path = sys.argv[2]
    user_hash = create_id()
    user_data = user_hash + '-' + HOST + ':' + str(PORT) + '\n'
    with open(tools.dht_path, 'w') as f:
        f.write(user_data)
    tools.dht = user_data
    tools.dht_storage = tools.dht_path.split('.')[0]
    os.mkdir(tools.dht_storage)
elif len(sys.argv) == 2:
    tools.dht_path = sys.argv[1]
    print("dht_path is: " + tools.dht_path)
    tools.dht_storage = tools.dht_path.split('.')[0]
    print("dht_storage is: " + tools.dht_storage)
    if os.path.isfile(tools.dht_path):
        with open(tools.dht_path, 'r') as f:
            tools.dht = f.readlines()
            user_data = tools.dht[0]  # The first element in dht is our node
            address = user_data.split('-')[1]
            HOST = address.split(':')[0]
            PORT = int(address.split(':')[1])

            user_hash = user_data.split('-')[0]
            user_ip = HOST + ':' + str(PORT)
            print("Your DHT: " + str(tools.dht))
            print("Your data: " + user_data)
else:
    print('Wrong arguments')
    sys.exit()

# server.dht_path = dht_path
server.start(HOST, PORT)


commands = ['help - show this message', 'id - print your user_hash', 'get - update DHT', 'put - send file to DHT', 'search - search for a file']
while True:
    cmd = input("Your command: ")
    if cmd == 'help':
        print(commands)
    elif cmd == 'dht':
        print(str(tools.dht))
    elif cmd == 'get':
        get()
    elif cmd == 'id':
        print("Your id: " + user_hash)
    elif cmd == 'put' or cmd == 'search':
        filename = str(input("File name: "))
        if cmd == 'search':
            data = "<<search>>"
        else:
            with open(filename, 'r') as f:
                data = f.read()
        command = 'put:' + user_data + ':' + filename + '=' + data  # put:hash-127.0.0.1:33:file.txt=some_text
        print(filename)
        filename_hash = tools.create_hash(filename).replace("'", "")

        similarities = dict(tools.get_similarity(filename_hash))
        for sim in similarities.keys():
            value = similarities[sim]  # Get [similarity, node_hash] of the current node in 'similarities' dictionary
            if value[1] == user_hash:  # If this is our hash, we remove it from the dictionary
                similarities.pop(sim)
                break

        similarities = list(similarities.keys())
        similarities = similarities[:5]  # Get first five nodes that have the best similarity with data_hash
        put(similarities, command)
    else:
        print('Wrong command')


