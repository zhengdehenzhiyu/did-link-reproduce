import socket
import ssl
import requests
import base58
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# 配置
HOST = '0.0.0.0'
PORT = 8443
LEDGER_URL = "http://localhost:9000"

def get_did_from_cert(cert_der):
    """从证书的 SAN 扩展中提取 DID"""
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    try:
        san = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        # 假设 DID 存在于 URI 字段中 (论文实现方式)
        did_uri = san.value.get_values_for_type(x509.UniformResourceIdentifier)[0]
        return did_uri, cert.public_key()
    except Exception as e:
        print(f"Error parsing cert: {e}")
        return None, None

def verify_did_binding(did, cert_pub_key):
    """核心逻辑：去账本查询 DID，并比对公钥 (修复版)"""
    print(f"[*] Verifying DID: {did} on Ledger...")
    
    did_short = did.split(":")[-1]
    
    try:
        # 查询账本
        response = requests.get(f"{LEDGER_URL}/ledger/domain", params={"query": did_short})
        
        # 检查 HTTP 状态
        if response.status_code != 200:
            print(f"[!] Ledger returned status {response.status_code}")
            return False
            
        data = response.json()
        
        if not data.get("results"):
            print(f"[!] DID {did} not found on ledger!")
            return False
            
        # --- 修复部分：正确解析嵌套的 JSON 结构 ---
        txn = data["results"][0]
        ledger_verkey_str = None
        
        # 尝试路径 1: 标准 Indy 结构 (txn -> data -> verkey)
        if "txn" in txn and "data" in txn["txn"]:
            ledger_verkey_str = txn["txn"]["data"].get("verkey")
        # 尝试路径 2: 某些版本的扁平结构
        elif "verkey" in txn:
            ledger_verkey_str = txn["verkey"]
            
        if not ledger_verkey_str:
            print(f"[!] Could not find 'verkey' in ledger response: {txn}")
            return False
        # ----------------------------------------

        print(f"    > Ledger Verkey: {ledger_verkey_str}")
        
        # 3. 将证书里的公钥转换为同样的格式 (Base58) 进行比对
        cert_pub_bytes = cert_pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        cert_verkey_str = base58.b58encode(cert_pub_bytes).decode('utf-8')
        print(f"    > Cert Public Key: {cert_verkey_str}")
        
        if ledger_verkey_str == cert_verkey_str:
            print("[+] SUCCESS: Key Binding Verified! The certificate is valid.")
            return True
        else:
            print("[!] FAILURE: Keys do not match! Potential Impersonation.")
            return False
            
    except Exception as e:
        print(f"[!] Ledger connection/parsing error: {e}")
        import traceback
        traceback.print_exc()
        return False

def start_server():
    # 创建 SSL 上下文
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # 加载自己的身份
    context.load_cert_chain(certfile="server_entity_cert.pem", keyfile="server_entity_key.pem")
    # 强制要求客户端提供证书 (mTLS)
    context.verify_mode = ssl.CERT_REQUIRED
    # 因为是自签名，我们需要禁用标准的 CA 检查，改用我们自己的 DID 检查
    context.check_hostname = False
    context.load_verify_locations(cafile="client_entity_cert.pem") # 临时信任，实际逻辑在下面

    bindsocket = socket.socket()
    bindsocket.bind((HOST, PORT))
    bindsocket.listen(5)
    print(f"[*] Server listening on {HOST}:{PORT}")

    while True:
        try:
            newsocket, fromaddr = bindsocket.accept()
            conn = context.wrap_socket(newsocket, server_side=True)
            print(f"[*] Connection from {fromaddr}")
            
            # --- 论文核心复现：DID 验证逻辑 ---
            # 获取客户端证书
            client_cert = conn.getpeercert(binary_form=True)
            if client_cert:
                did, pub_key = get_did_from_cert(client_cert)
                if did:
                    is_valid = verify_did_binding(did, pub_key)
                    if is_valid:
                        conn.send(b"Welcome to DID-TLS Secure Server!")
                    else:
                        conn.send(b"Identity Verification Failed!")
                        conn.close()
                        continue
            # --------------------------------
            
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
        except Exception as e:
            print(f"Connection error: {e}")

if __name__ == "__main__":
    start_server()