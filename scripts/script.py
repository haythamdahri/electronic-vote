from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Getting a Key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

print(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption()))

# Storing Keys
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open('private_key.pem', 'wb') as f:
    f.write(pem)
print("Private key saved successflly")

pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('public_key.pem', 'wb') as f:
    f.write(pem)

print("Public key saved successflly")

# Reading Keys
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# ============== Encrypting ==============
message = b'encrypt me!'

encrypted = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA512()),
        algorithm=hashes.SHA512(),
        label=None
    )
)

original_message = private_key.decrypt(
    encrypted,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA512()),
        algorithm=hashes.SHA512(),
        label=None
    )
)

print(f"Original message: {original_message}")
print(f"message == original_message ? {message == original_message}")

# Signing

message = b"A message I want to sign"
signature = private_key.sign(message, padding.PSS(
    mgf=padding.MGF1(hashes.SHA512()),
    salt_length=padding.PSS.MAX_LENGTH
), hashes.SHA512())

# Veifying signature
try:
    public_key.verify(signature, message,
                      padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH),
                      hashes.SHA512()
                      )
except InvalidSignature as e:
    print(e)
    print("Signature does not passed!")
else:
    print("Signature passed successflly")

# Encrypting and Decrypting Files
f = open('test.txt', 'rb')
message = f.read()
f.close()

encrypted = b'data from encryption'
f = open('test.encrypted', 'wb')
f.write(encrypted)
f.close()


digest1 = hashes.Hash(hashes.SHA512(), backend=default_backend())
digest1.update(b"HAYTHAM DAHRI")
original_hashed_text = digest1.finalize()

digest2 = hashes.Hash(hashes.SHA512(), backend=default_backend())
digest2.update(b"HAYTHAM DAHRI")
new_hashed_text = digest2.finalize()

print(f"Original hashed text: {original_hashed_text}")
print(f"New hash: {new_hashed_text}")

print(original_hashed_text == new_hashed_text)


