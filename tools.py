import Levenshtein
from hashlib import sha1

dht = ()  # List with hash table from dht_path
dht_path = ""  # Path to the contents of the hash table
dht_storage = ""  # Directory with files from other nodes


def create_hash(text):
    hash_obj = sha1(str.encode(text))
    hashed = hash_obj.hexdigest()
    return hashed


def get_similarity(data_hash):
    similarities = {}

    for node in dht:
        if '-' not in node:
            continue

        node = node.replace('\n', '')
        node = node.split('-')  # Example of node: <random_hash>-127.0.0.1:4444, so we need to split it by '-'
        node_hash = node[0]
        node_address = node[1]
        similarity = Levenshtein.ratio(str(data_hash), node_hash)
        print("Similarity " + str(data_hash) + " and " + node_hash + '-' + node_address + " is " + str(similarity))
        similarities[node_hash + '-' + node_address + '\n'] = similarity

    sorted_similarities = sorted(similarities.items(), key=lambda x: x[1], reverse=True)  # Sort in descending order
    sorted_similarities = tuple(dict(sorted_similarities).keys())
    return sorted_similarities
