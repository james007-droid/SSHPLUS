#!/usr/bin/env python3
# encoding: utf-8
# scottssh

import socket
import threading
import select
import signal
import sys
import time
import getopt

MSG = ''
COR = '<font color="null">'
FTAG = '</font>'
PASS = ''
LISTENING_ADDR = '0.0.0.0'

try:
    LISTENING_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    LISTENING_PORT = 80

BUFLEN = 8196 * 8
TIMEOUT = 60
DEFAULT_HOST = "127.0.0.1:22"
RESPONSE = f'HTTP/1.1 101 {COR}{MSG}{FTAG} \r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        try:
            self.soc.bind((self.host, self.port))
            self.soc.listen(5)
            self.running = True
            self.printLog(f"Servidor iniciado com sucesso, escutando em {self.host}:{self.port}")
            self.accept_connections()
        except socket.error as e:
            self.printLog(f"Erro ao iniciar o servidor: {str(e)}")
            self.running = False
        finally:
            self.soc.close()

    def accept_connections(self):
        while self.running:
            try:
                c, addr = self.soc.accept()
                c.setblocking(1)
                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
            except socket.timeout:
                continue
            except Exception as e:
                self.printLog(f"Erro ao aceitar conexão: {str(e)}")

    def printLog(self, log):
        with self.logLock:
            print(log)

    def addConn(self, conn):
        with self.threadsLock:
            if self.running:
                self.threads.append(conn)

    def removeConn(self, conn):
        with self.threadsLock:
            if conn in self.threads:
                self.threads.remove(conn)

    def close(self):
        self.running = False
        with self.threadsLock:
            threads = list(self.threads)
            for c in threads:
                c.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        super().__init__()
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = b''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        self.close_client()
        self.close_target()

    def close_client(self):
        if not self.clientClosed:
            try:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
            except socket.error as e:
                self.server.printLog(f"Erro ao fechar cliente: {str(e)}")
            finally:
                self.clientClosed = True

    def close_target(self):
        if not self.targetClosed:
            try:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
            except socket.error as e:
                self.server.printLog(f"Erro ao fechar alvo: {str(e)}")
            finally:
                self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
            if not self.client_buffer:
                raise ValueError("Buffer do cliente está vazio")

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host') or DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')
            if split:
                self.client.recv(BUFLEN)

            if self.authenticate_client(hostPort):
                self.method_CONNECT(hostPort)
            else:
                self.client.send(b'HTTP/1.1 403 Forbidden!\r\n\r\n')

        except Exception as e:
            self.log += f' - erro: {str(e)}'
            self.server.printLog(self.log)
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        header_value = ''
        try:
            aux = head.find(f'{header}: '.encode())
            if aux != -1:
                aux = head.find(b':', aux)
                head = head[aux+2:]
                aux = head.find(b'\r\n')
                if aux != -1:
                    header_value = head[:aux].decode()
        except Exception as e:
            self.server.printLog(f"Erro ao encontrar cabeçalho {header}: {str(e)}")
        return header_value

    def authenticate_client(self, hostPort):
        passwd = self.findHeader(self.client_buffer, 'X-Pass')
        if PASS:
            return passwd == PASS
        return hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost')

    def connect_target(self, host):
        try:
            i = host.find(':')
            port = int(host[i+1:]) if i != -1 else 443 if self.method == 'CONNECT' else 80
            host = host[:i] if i != -1 else host
            soc_family, soc_type, proto, _, address = socket.getaddrinfo(host, port)[0]
            self.target = socket.socket(soc_family, soc_type, proto)
            self.target.connect(address)
            self.targetClosed = False
        except socket.error as e:
            self.server.printLog(f"Erro ao conectar ao alvo: {str(e)}")
            raise

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        try:
            self.connect_target(path)
            self.client.sendall(RESPONSE.encode())
            self.server.printLog(self.log)
            self.doCONNECT()
        except Exception as e:
            self.server.printLog(f"Erro ao lidar com método CONNECT: {str(e)}")

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while not error:
            count += 1
            try:
                recv, _, err = select.select(socs, [], socs, 3)
                if err:
                    error = True
                    self.server.printLog("Erro de socket detectado em select().")
                if recv:
                    for in_ in recv:
                        data = in_.recv(BUFLEN)
                        if data:
                            if in_ is self.target:
                                self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]
                            count = 0
                        else:
                            error = True
                            self.server.printLog("Conexão fechada pela outra extremidade.")
                            break
                if count == TIMEOUT:
                    error = True
                    self.server.printLog("Tempo limite atingido para a conexão.")
            except socket.error as e:
                self.server.printLog(f"Erro de socket durante transferência: {str(e)}")
                error = True
            except Exception as e:
                self.server.printLog(f"Erro inesperado durante transferência de dados: {str(e)}")
                error = True

def print_usage():
    print('Uso: proxy.py -p <porta>')
    print('       proxy.py -b <ip> -p <porta>')
    print('       proxy.py -b 0.0.0.0 -p 22')

def parse_args(argv):
    global LISTENING_ADDR, LISTENING_PORT
    try:
        opts, args = getopt.getopt(argv, "hb:p:", ["bind=", "port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)

def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print("\033[0;34m━" * 8, "\033[1;32m PROXY WEBSOCKET", "\033[0;34m━" * 8, "\n")
    print("\033[1;33mIP:\033[1;32m " + LISTENING_ADDR)
    print("\033[1;33mPORTA:\033[1;32m " + str(LISTENING_PORT) + "\n")
    print("\033[0;34m━" * 10, "\033[1;32m turbonet2023", "\033[0;34m━\033[1;37m" * 11, "\n")

    server = Server(host, port)
    server.start()

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print('Parando...')
        server.close()

if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()
