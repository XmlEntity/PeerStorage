import socket
import threading
import pickle
import os
import tools


def connection(conn, addr):
    while True:
        data = conn.recv(1024)
        if not data:
            conn.close()
            break

        data = data.decode(encoding='utf-8')
        data = data.split(':')  # Example of the request part: put:<random_hash>-127.0.0.1:4444
        cmd = data[0]  # Get requested command ('put' or 'get')
        sender_address = data[1]  # Get sender's "hash-127.0.0.1" from received data
        address_splitted = sender_address.split('-')  # Split address to get an ip
        sender_hash = address_splitted[0]  # We removed "-127.0.0.1" from the address to get sender's hash
        port = data[2]
        dht_append(sender_address + ':' + port)

        if cmd == 'bootstrap':
            print("Bootstrap request!")
            conn.sendall(pickle.dumps(tools.dht))
        elif cmd == 'get':  # Example of get command: get:hash-127.0.0.1:33:file.txt=some_text
            get_content = data[3]  # Get the put request metadata (file.txt=some_text)
            get_content = get_content.split('=')
            file_name = get_content[0]
            file_content = get_content[1]
            file_hash = tools.create_hash(file_name)
            file_path = tools.dht_storage + '/' + file_hash  # Path to %file_hash%
            
            if '<<search>>' in file_content and os.path.isfile(file_path):
                # If the file content is '<<search>>', we must find it
                with open(file_path, 'r') as f:
                    result = f.read()
            else:
                # And if we couldn't find the requested file, then we
                # use "put_handler" function to find out which nodes can have it.
                # This function is also used to save files from 'put' request and
                # send nodes that are "closer" to the file hash.
                result = get_handler(file_hash, sender_hash.replace('\n', ''))
            conn.sendall(pickle.dumps(result))
        elif cmd == 'put':
            put_content = data[3]  # Get the put request metadata (file.txt=some_text)
            put_content = put_content.split('=')
            file_name = put_content[0]
            file_content = put_content[1]
            file_hash = tools.create_hash(file_name)
            file_path = tools.dht_storage + '/' + file_hash

            with open(file_path, 'w') as f:
                f.write(file_content)
        else:
            conn.sendall(pickle.dumps("[wrong_command]"))
        print("Data from node: " + str(data))
        conn.close()
        break


def get_handler(file_hash, sender_hash):
    result = '[OK]'

    sorted_similarities = tools.get_similarity(file_hash)

    nodes_to_send = []

    for i in range(len(sorted_similarities)):
        node_metadata = sorted_similarities[i].split('-')
        node_hash = node_metadata[0]

        if i > 2:  # i - number of nodes we want to include in the best similarity list
            break
        elif node_hash == sender_hash:
            # If the node in current iteration is equal to
            # sender's hash, which is being processed by 'connection' function,
            # then we need to skip the iteration.
            continue

        nodes_to_send.append(sorted_similarities[i])

    if len(nodes_to_send) != 0:
        result = nodes_to_send
    print("Nodes to send: " + str(nodes_to_send))
    return result


def listening(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen()

    print("Server started on " + host + ':' + str(port))

    while True:
        conn, addr = sock.accept()
        print('Connected by', addr)
        conn_thread = threading.Thread(target=connection, args=(conn, addr,))
        conn_thread.start()


def dht_append(node):
    # This function checks if a node exists in our hash table,
    # and if not, we add a new node to the hash table.

    if node.replace('\n', '') not in str(tools.dht):
        print("Appended: " + node)
        if '\n' not in node:
            node += '\n'
        with open(tools.dht_path, 'a') as f:
            f.write(node)
        with open(tools.dht_path, 'r') as f:
            updated_dht = f.readlines()
        tools.dht = tuple(updated_dht)


def start(host, port):
    listen_thread = threading.Thread(target=listening, args=(host, int(port), ))
    listen_thread.start()


if __name__ == "__main__":
    print('Error')
