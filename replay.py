import socket
from select import select

server_facing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_facing.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_facing.connect(('localhost', 8081))

client_facing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_facing.bind(('localhost', 8082))
client_facing.listen(1)
client_conn, client_addr = client_facing.accept()

inputs = [client_conn, server_facing]

num_client_acks = 0
handshake_done = False

while inputs:
    readable, _, _ = select(inputs, [], [])
    if len(readable) > 0:
        for sock in readable:
            if sock == server_facing:
                server_message = server_facing.recv(1024)
                print('Server', server_message)
                client_conn.sendall(server_message)
            elif sock == client_conn:
                client_message = client_conn.recv(1024)
                print('Client', client_message)
                server_facing.sendall(client_message)

                # Check for end of handshake
                if num_client_acks == 4:
                    handshake_done = True
                elif client_message == b'ACK':
                    num_client_acks += 1
                # Do a replay if it's a regular message
                if handshake_done:
                    server_facing.recv(1024)
                    server_facing.sendall(client_message)

