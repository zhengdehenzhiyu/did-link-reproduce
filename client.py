import socket
import ssl

HOST = 'localhost'
PORT = 8443

def start_client():
    # 创建 SSL 上下文
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # 关键：加载客户端自己的 DID 证书
    context.load_cert_chain(certfile="client_entity_cert.pem", keyfile="client_entity_key.pem")
    
    # 不验证标准 CA (因为是自签名的)，我们依赖 DID 验证
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE 

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        conn = context.wrap_socket(s, server_hostname=HOST)
        print(f"[*] Connecting to {HOST}:{PORT}...")
        conn.connect((HOST, PORT))
        
        # 接收服务器的响应
        data = conn.recv(1024)
        print(f"[*] Server Response: {data.decode('utf-8')}")
        
        conn.close()
    except ConnectionRefusedError:
        print("[!] Connection failed. Make sure server.py is running.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    start_client()