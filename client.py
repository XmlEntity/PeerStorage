import socket
import sys
import server
import os
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


def upload_file(filename, content):
    file_similarities = list(tools.get_similarity(filename_hash))
    file_similarities.remove(user_data)
    file_similarities = tuple(file_similarities)
    for node in file_similarities[:3]:  # The number of nodes that will receive a file
        node_data = node.split('-')[1]
        node_data = node_data.split(':')  # Get an address from the node data and split it to get an ip and port
        ip = node_data[0]
        port = int(node_data[1])
        command = str.encode('put:' + user_data + ':' + filename + '=' + content)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))
                s.sendall(command)
                data = s.recv(4096)
        except Exception as ex:
            print(str(ex))
            pass


def update_db(nodes):
    for i in range(len(nodes)):
        if '\n' not in nodes[i]:
            nodes[i] += '\n'
    temporary_dht = list(tools.dht)  # Create a temporary variable to add data to DHT (variable type is tuple)
    temporary_dht.pop(0)
    temporary_dht.extend(nodes)
    temporary_dht = list(set(temporary_dht))  # temporary_dht contains only unique data
    temporary_dht.insert(0, user_data)
    tools.dht = tuple(temporary_dht)
    similarities = tools.get_similarity(user_hash)  # Sort the DHT by our hash

    with open(tools.dht_path, 'w') as f:
        f.writelines(similarities)
    tools.dht = tuple(similarities)


def bootstrap():
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
                s.sendall(str.encode('bootstrap' + ':' + user_data))
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
                tools.dht = tuple(new_dht)
            break
        except Exception as ex:
            print(str(ex))
            continue


def get(similarities, command):
    print("Sort_similarities: " + str(similarities))

    received_nodes = []
    for sim in similarities:
        print(str(sim))
        if '-' in sim:  # If this is a node that we received from other node (other nodes sends us ip with hash)
            sim = sim.split('-')[1]

        node_ip = sim.split(':')[0]
        node_port = sim.split(':')[1].replace('\n', '')

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
                        if user_ip in node:
                            nodes.remove(node)
                        elif node.replace('\n', '') in str(similarities):
                            nodes.remove(node)

                    if len(nodes) == 1 and nodes[0].replace('\n', '') in str(similarities):
                        # This fixes a bug when 'for' loop in the lines above can't remove the last element
                        nodes.clear()
                    elif len(nodes) != 0:  # If received list contains at least one element
                        similarities.extend(nodes)
                        received_nodes.extend(nodes)
                    received_nodes = list(set(received_nodes))

                else:  # elif '[OK]' not in str(nodes) - draft
                    print("File found! " + filename + " is:\n" + str(pickle.loads(recvdata)))
                    break  # Break loop if we found the file
        except Exception as ex:
            print('Exception: ' + str(ex))
            pass
    print("Received nodes is: " + str(received_nodes))
    print("Now similarities is: " + str(similarities))
    update_db(received_nodes)  # After that we should update the dht database with theese nodes
    if '<<search>>' not in command:
        # When we updated the DHT and sorted it, we should call the upload_file function
        upload_file(filename, data)


if len(sys.argv) == 3 and not os.path.isfile(sys.argv[2]):
    PORT = sys.argv[1]
    tools.dht_path = sys.argv[2]
    user_hash = create_id()
    user_data = user_hash + '-' + HOST + ':' + str(PORT) + '\n'
    with open(tools.dht_path, 'w') as f:
        f.write(user_data)
    tools.dht = tuple(user_data)
    tools.dht_storage = tools.dht_path.split('.')[0]
    os.mkdir(tools.dht_storage)
elif len(sys.argv) == 2:
    tools.dht_path = sys.argv[1]
    print("dht_path is: " + tools.dht_path)
    tools.dht_storage = tools.dht_path.split('.')[0]
    print("dht_storage is: " + tools.dht_storage)
    if os.path.isfile(tools.dht_path):
        with open(tools.dht_path, 'r') as f:
            tools.dht = tuple(f.readlines())
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

server.start(HOST, PORT)


commands = ['help - show this message', 'id - print your user_hash', 'update - update DHT', 'upload - send file to DHT', 'search - search for a file']
while True:
    cmd = input("Your command: ")
    if cmd == 'help':
        print(commands)
    elif cmd == 'dht':
        print(str(tools.dht))
    elif cmd == 'update':
        bootstrap()
    elif cmd == 'id':
        print("Your id: " + user_hash)
    elif cmd == 'upload' or cmd == 'search':
        filename = str(input("File name: "))
        if cmd == 'search':
            data = "<<search>>"
        else:
            with open(filename, 'r') as f:
                data = f.read()
        command = 'get:' + user_data + ':' + filename + '=' + data  # put:hash-127.0.0.1:33:file.txt=some_text
        print(filename)
        filename_hash = tools.create_hash(filename)
        similarities = list(tools.get_similarity(filename_hash))

        for i in range(len(similarities)):
            node_data = similarities[i].split('-')
            node_hash = node_data[0]

            if node_hash == user_hash:  # If this is our hash, we remove it from the dictionary
                similarities.pop(i)
                break

        similarities = similarities[:5]  # Get first five nodes that have the best similarity with filename_hash
        get(similarities, command)
    else:
        print('Wrong command')


