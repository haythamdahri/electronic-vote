import codecs
import os
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from django.core.files import File

from ElectronicVote.settings import BASE_DIR
from SecuredVote.models import Signature, Revision, Vote, Voter


def generate_keys(voter):
    # Used to check if the user has already keys pairs
    keys_generated = False
    try:
        # for private key
        file = open(os.path.join(BASE_DIR) + "/media/keys/" + voter.user.username + "_private_key.pem", "rb")
        # for public key
        file = open(os.path.join(BASE_DIR) + "/media/keys/" + voter.user.username + "_public_key.pem", "rb")
        keys_generated = True
    except Exception as ex:
        print(ex)
        pass

    if not keys_generated:

        # Open temprory saving file for private key
        file = open(os.path.join(BASE_DIR) + "/media/" + "temprory_private_key.pem", "wb+")

        # Remove the private key file if exists to prevent space management problems
        if os.path.exists(os.path.join(BASE_DIR) + "/media/keys/" + voter.user.username + "_private_key.pem"):
            os.remove(os.path.join(BASE_DIR) + "/media/keys/" + voter.user.username + "_private_key.pem")
        if os.path.exists(os.path.join(BASE_DIR) + "/media/keys/" + voter.user.username + "_public_key.pem"):
            os.remove(os.path.join(BASE_DIR) + "/media/keys/" + voter.user.username + "_public_key.pem")

        # Getting a Key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Getting private key text
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Write private key in the file first
        file.write(pem)

        # Save user private key
        voter.private_key.save("keys/" + voter.user.username + "_private_key.pem", File(file), save=True)
        file.close()

        # Open temprory saving file for public key
        file = open(os.path.join(BASE_DIR) + "/media/" + "temprory_public_key.pem", "wb+")

        # Getting public key text
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Write public key in the file first
        file.write(pem)

        # Save user private key
        voter.public_key.save("keys/" + voter.user.username + "_public_key.pem", File(file), save=True)
        file.close()

        voter.save()
    return voter


def encrypt_data(voter, candidate):
    # Make sure that the keys pair are generated
    voter = generate_keys(voter)

    dummy = voter_public_key = voter_private_key = None
    with open(voter.private_key.path, "rb") as key_file:
        voter_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    with open(voter.public_key.path, "rb") as key_file:
        voter_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Extract private and public key of co and do
    with open(os.path.join(BASE_DIR) + "/privacy/" + "co_public_key.pem", "rb") as key_file:
        co_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    with open(os.path.join(BASE_DIR) + "/privacy/" + "do_public_key.pem", "rb") as key_file:
        do_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Open public(For CO) file if exists or create it(all content will be overwritten)
    # Encrypt data with CO public key (Decryption only with CO private key)
    co_file = open(os.path.join(BASE_DIR) + "/media/" + "data_pub.encrypt", "wb+")

    # Open public(for DO) file if exists or create it(all content will be overwritten)
    # Encrypt data with DO public key (Decryption only with DO private key)
    do_file = open(os.path.join(BASE_DIR) + "/media/" + "data_pub.encrypt", "wb+")

    # Encrypt voter id  using his private key
    # Decryption will be with the voter public key(Access allowed to all authorities)
    # voter_identifier_message is voter id
    # voting_bulletin_message is candidate id
    voter_identifier_message = str.encode(str(voter.id))
    co_voter_identifier_ciphertext = co_public_key.encrypt(
        voter_identifier_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    do_voter_identifier_ciphertext = do_public_key.encrypt(
        voter_identifier_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Encrypt voting bulletin using DO private key
    voting_bulletin_message = str.encode(str(candidate.id))
    voting_bulletin_ciphertext = do_public_key.encrypt(
        voting_bulletin_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write encrypted data into co_file and do_file too
    co_file.write(str.encode(str(co_voter_identifier_ciphertext)))
    co_file.write(str.encode("\n"))
    co_file.write(str.encode(str(voting_bulletin_ciphertext)))

    do_file.write(str.encode(str(do_voter_identifier_ciphertext)))
    co_file.write(str.encode("\n"))
    do_file.write(str.encode(str(voting_bulletin_ciphertext)))

    # Sign the message with voter private key
    message = str.encode(f"Message: {voter} | time: {time.time()}")
    signature = voter_private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Create a new signature

    signature = Signature.objects.create(sig=signature, message=message, public_key=voter.public_key)
    signature.save()

    return co_file, do_file, signature

    # Verification (In the CO and DO views)


def verify_signature(signature):
    # Voter public key
    voter_public_key = ""

    print(signature.sig)

    # Extract signature text
    with open(signature.public_key.path, "rb") as key_file:
        voter_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Verification => Throws InvalidSignature exception if does not verify
    try:
        print(signature.sig)
        print(signature.message)
        verification = voter_public_key.verify(
            signature.sig,
            signature.message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Validate signature after verification
        signature.is_valid = True
        signature.save()
        return True
    except Exception as e:
        signature.is_valid = False
        signature.save()
        return False

def decrypt_pending(pending):
    try:
        # Decrypt pending
        # Extract private and public key of co and do
        with open(os.path.join(BASE_DIR) + "/privacy/" + "co_public_key.pem", "rb") as key_file:
            co_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        with open(os.path.join(BASE_DIR) + "/privacy/" + "co_private_key.pem", "rb") as key_file:
            co_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # co_file (Clair text separated with \n)
        co_file = open(pending.co_file.path, "rb")
        voter_id_ciphertext = co_file.readline().decode('unicode-escape').strip()[2:-1].encode('ISO-8859-1')

        # Get voter id
        voter_id = co_private_key.decrypt(
            voter_id_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Retrieve vote from vode_id
        voter = Voter.objects.filter(id=voter_id)
        if voter.exists():
            voter = voter[0]
            voter.is_voted = True
            voter.save()
        else:
            return None

        # Create new revision after decryption
        revision = Revision.objects.create(pending=pending, do_file=pending.do_file)
        revision.save()

        # Mark pending as done
        pending.done = True
        pending.save()

        return voter
    except Exception as e:
        print(e)
        pending.done = True
        pending.is_valid = False
        pending.save()
        return None