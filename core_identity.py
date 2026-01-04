import os
import json
import base58
import requests
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime

# 配置：本地账本的注册接口
LEDGER_URL = "http://localhost:9000"

class IdentityManager:
    def __init__(self, alias):
        self.alias = alias
        self.private_key = None
        self.public_key = None
        self.did = None
        self.verkey = None

    def generate_keys(self):
        """1. 生成 Ed25519 密钥对和 DID"""
        print(f"[{self.alias}] Generating keys...")
        # 生成私钥
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # 导出公钥字节
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # 生成 DID (Indy 风格: base58 编码的前 16 字节公钥)
        # 注意：这是一种简化的 DID 生成方式，仅用于复现实验
        self.did = f"did:sov:{base58.b58encode(pub_bytes[:16]).decode('utf-8')}"
        self.verkey = base58.b58encode(pub_bytes).decode('utf-8')
        
        print(f"  > Generated DID: {self.did}")
        print(f"  > Verkey: {self.verkey}")

    def register_on_ledger(self):
        """2. 调用本地 HTTP 接口注册 DID (上链)"""
        print(f"[{self.alias}] Registering DID on Ledger ({LEDGER_URL})...")
        
        # VON Network 提供了一个 /register 接口方便开发使用
        payload = {
            "did": self.did.split(":")[-1], # 只需要最后一段
            "verkey": self.verkey,
            "alias": self.alias,
            "role": "TRUST_ANCHOR"  # 赋予写入权限
        }
        
        try:
            # 注意：实际通过 HTTP 注册通常只需要传递 did 和 verkey
            # 如果已有 DID，/register 会尝试注册它
            res = requests.post(f"{LEDGER_URL}/register", json=payload)
            if res.status_code == 200:
                print("  > Registration Success!")
            else:
                print(f"  > Warning: Registration returned {res.status_code}. It might already exist.")
        except Exception as e:
            print(f"  > Error connecting to ledger: {e}")
            print("  ! 请确保 von-network 容器正在运行且端口 9000 可访问")

    def generate_did_certificate(self):
        """3. 生成包含 DID 的自签名 X.509 证书"""
        print(f"[{self.alias}] Generating X.509 Certificate with DID extension...")
        
        # 构建证书主题
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.alias), # CN 任意
        ])
        
        # 关键：将 DID 放入 SAN (Subject Alternative Name) 扩展中
        # 论文提到放在 URI 字段
        san = x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(self.did)
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(san, critical=False)
            .sign(self.private_key, algorithm=None) # Ed25519 不需要摘要算法
        )
        
        # 保存文件
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # 写入硬盘
        with open(f"{self.alias}_cert.pem", "wb") as f:
            f.write(cert_pem)
        with open(f"{self.alias}_key.pem", "wb") as f:
            f.write(key_pem)
            
        print(f"  > Saved: {self.alias}_cert.pem and {self.alias}_key.pem")

# 执行流程
if __name__ == "__main__":
    # 模拟生成 Server 端的身份
    server = IdentityManager("server_entity")
    server.generate_keys()
    server.register_on_ledger()
    server.generate_did_certificate()

    print("-" * 20)

    # 模拟生成 Client 端的身份
    client = IdentityManager("client_entity")
    client.generate_keys()
    client.register_on_ledger()
    client.generate_did_certificate()
    
    print("\nDONE: 身份准备完成。请检查目录下的 .pem 文件。")