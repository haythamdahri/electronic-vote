import os
import os
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from django.contrib.auth.models import User
from django.core.files import File

from ElectronicVote.settings import BASE_DIR
from SecuredVote.models import Signature, Revision, Voter, Candidate, Vote, Pending


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
        pass

    if not keys_generated:

        # Remove the private key file if exists to prevent space management problems
        if os.path.exists(os.path.join(BASE_DIR) + "/media/" + "temprory_public_key.pem"):
            os.remove(os.path.join(BASE_DIR) + "/media/" + "temprory_public_key.pem")
        if os.path.exists(os.path.join(BASE_DIR) + "/media/" + "temprory_private_key.pem"):
            os.remove(os.path.join(BASE_DIR) + "/media/" + "temprory_private_key.pem")

        # Open temprory saving file for private key
        file = open(os.path.join(BASE_DIR) + "/media/" + "temprory_private_key.pem", "wb+")
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

    with open(os.path.join(BASE_DIR) + "/privacy/" + "de_public_key.pem", "rb") as key_file:
        de_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Open public(For CO) file if exists or create it(all content will be overwritten)
    # Encrypt data with CO public key (Decryption only with CO private key)

    co_file = open(os.path.join(BASE_DIR) + "/media/" + "co_data_pub.encrypt", "wb+")

    # Open public(for DO) file if exists or create it(all content will be overwritten)
    # Encrypt data with DO public key (Decryption only with DO private key)
    de_file = open(os.path.join(BASE_DIR) + "/media/" + "de_data_pub.encrypt", "wb+")

    # voter_identifier_message is voter id
    # voting_bulletin_message is candidate id
    # Encrypt voter id with co public key (decryption with co private key)
    voter_identifier_message = str.encode(str(voter.id))
    co_voter_identifier_ciphertext = co_public_key.encrypt(
        voter_identifier_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )


    # DE cannot know which Voter we have in the message
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(voter_identifier_message)
    de_voter_hashed_identifier = digest.finalize()
    de_voter_identifier_ciphertext = de_public_key.encrypt(
        de_voter_hashed_identifier,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

    # Encoded candidate id
    voting_bulletin_message = str.encode(str(candidate.id))

    # Encrypt voting bulletin using CO private key for DE + Hash
    # Unauthorize CO to access candidate
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(voting_bulletin_message)
    co_voter_hashed_identifier = digest.finalize()
    co_voting_bulletin_ciphertext = co_public_key.encrypt(
        co_voter_hashed_identifier,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

    # Encrypt voting bulletin using DE private key for DE
    de_voting_bulletin_ciphertext = de_public_key.encrypt(
        voting_bulletin_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

    # Write encrypted data into co_file and de_file too
    co_file.write(str.encode(str(co_voter_identifier_ciphertext)))
    co_file.write(str.encode("\n"))
    co_file.write(str.encode(str(co_voting_bulletin_ciphertext)))

    de_file.write(str.encode(str(de_voter_identifier_ciphertext)))
    de_file.write(str.encode("\n"))
    de_file.write(str.encode(str(de_voting_bulletin_ciphertext)))

    # Sign the message with voter private key
    message = str.encode(f"Message: {voter} | time: {time.time()}")
    signature = voter_private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA512()
    )

    # Create a new signature
    signature = Signature.objects.create(sig=signature, message=message, public_key=voter.public_key)
    signature.save()

    return co_file, de_file, signature

    # Verification (In the CO and DO views)


def verify_signature(signature):
    # Voter public key
    public_key = ""

    # Extract signature text
    with open(signature.public_key.path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Verification => Throws InvalidSignature exception if does not verify
    try:
        print(signature.sig)
        print(signature.message)
        verification = public_key.verify(
            signature.sig,
            signature.message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        # Validate signature after verification
        signature.is_valid = True
        signature.save()
        return True
    except Exception as e:
        signature.is_valid = False
        signature.save()
        pending = Pending.objects.filter(signature=signature)
        revision = Revision.objects.filter(signature=signature)
        if pending.exists():
            pending = pending[0]
            pending.done = True
            pending.is_valid = False
            pending.save()
        else:
            revision = revision[0]
            revision.done = True
            revision.is_valid = False
            revision.save()
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

        with open(os.path.join(BASE_DIR) + "/privacy/" + "de_public_key.pem", "rb") as key_file:
            de_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        with open(os.path.join(BASE_DIR) + "/privacy/" + "co_private_key.pem", "rb") as key_file:
            co_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        with open(os.path.join(BASE_DIR) + "/privacy/" + "de_private_key.pem", "rb") as key_file:
            de_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # co_file (Clair text separated with \n)
        co_file = open(pending.co_file.path, "rb")
        voter_id_ciphertext = co_file.readline().decode('unicode-escape').strip()[2:-1].encode('ISO-8859-1')
        candidate_id_ciphertext_to_co = co_file.readline().decode('unicode-escape').strip()[2:-1].encode('ISO-8859-1')

        # co_file (Clair text separated with \n)
        de_file = open(pending.de_file.path, "rb")
        unused_voter_id_ciphertext = de_file.readline().decode('unicode-escape').strip()[2:-1].encode('ISO-8859-1')
        candidate_id_ciphertext = de_file.readline().decode('unicode-escape').strip()[2:-1].encode('ISO-8859-1')

        # Get voter id
        voter_id = co_private_key.decrypt(
            voter_id_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )

        candidate_id_hashed = co_private_key.decrypt(
            candidate_id_ciphertext_to_co,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
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

        # Sign the message with voter private key
        message = str.encode(f"Message: {pending} | time: {time.time()}")
        signature = co_private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )

        # Encrypt voter identity and encrypted bulletin
        # Encrypt Voter id with co_public_key in order to prevent its read by do authority
        # hash voter id to prevent access from DE authority
        voter_identifier_message = str.encode(str(voter.id))

        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(voter_identifier_message)
        voter_identifier_message_hashed = digest.finalize()

        voter_identifier_ciphertext = de_public_key.encrypt(
            voter_identifier_message_hashed,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )

        # Hashed candidate id will be sent directly without encryption because it's already hashed and can't be retrieved
        # ONe way hash
        candidate_id_ciphertext_to_co_message = str.encode(str(candidate_id_hashed))
        print(f"Candidate hash in CO: {candidate_id_hashed}")

        co_encryption_file = open(os.path.join(BASE_DIR) + "/media/" + "co_encrypted_file.encrypt", "wb+")
        co_encryption_file.write(str.encode(str(voter_identifier_ciphertext)))
        co_encryption_file.write(str.encode("\n"))
        co_encryption_file.write(candidate_id_ciphertext_to_co_message)

        # Create a new signature
        co_public_key_file = open(os.path.join(BASE_DIR) + "/privacy/" + "co_public_key.pem", "r")
        signature = Signature.objects.create(sig=signature, message=message)
        signature.public_key.save("signatures/" + "temp_co_file.encrypt", File(co_public_key_file), save=True)
        signature.save()
        co_public_key_file.close()

        # Create new revision after decryption
        revision = Revision.objects.create(pending=pending, de_file=pending.de_file, signature=signature)
        revision.co_file.save("final_co_file.encrypt", File(co_encryption_file), save=True)
        revision.save()
        co_encryption_file.close()

        # Mark pending as done
        pending.done = True
        pending.is_valid = True
        pending.save()

        return voter
    except Exception as e:
        print(e)
        # If decryption didn't well, we have to mark the operation as done but with valid False
        pending.done = True
        pending.is_valid = False
        pending.save()
        return None


def decrypt_revision(revision):
    try:
        # Decrypt pending

        # Extract private and public key of co and do
        with open(os.path.join(BASE_DIR) + "/privacy/" + "co_public_key.pem", "rb") as key_file:
            co_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        with open(os.path.join(BASE_DIR) + "/privacy/" + "de_public_key.pem", "rb") as key_file:
            de_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        with open(os.path.join(BASE_DIR) + "/privacy/" + "co_private_key.pem", "rb") as key_file:
            co_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        with open(os.path.join(BASE_DIR) + "/privacy/" + "de_private_key.pem", "rb") as key_file:
            de_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # co_file (Clair text separated with \n)
        co_file = open(revision.co_file.path, "rb")
        voter_id_from_co_ciphertext = co_file.readline().decode('unicode-escape').strip()[2:-1].encode('ISO-8859-1')
        candidate_id_hashed_from_co = co_file.readline().decode('unicode-escape').strip()[2:-1].encode('ISO-8859-1')

        # de_file which sent by the voter
        de_file = open(revision.de_file.path, "rb")
        # No access to voter id because it's encrypted with CO public key
        voter_id_from_voter_ciphertext = de_file.readline().decode('unicode-escape').strip()[2:-1].encode('ISO-8859-1')
        candidate_id_from_voter_ciphertext = de_file.readline().decode('unicode-escape').strip()[2:-1].encode('ISO-8859-1')


        # DO cannot have the access into voter id
        # Get voter_id clear text and hash it to be compared with other hashed one from co
        voter_id_hashed_from_voter = de_private_key.decrypt(
            voter_id_from_voter_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )

        voter_id_hashed_from_co = de_private_key.decrypt(
            voter_id_from_co_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )


        # Get candidate id from voter
        candidate_id_from_voter = de_private_key.decrypt(
            candidate_id_from_voter_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )


        # Check signature
        # throw exception if signature fail
        if not verify_signature(revision.signature):
            raise ValueError("Invalid signature, invalid vote")

        # Retrieve candidate from database
        candidate = Candidate.objects.filter(id=candidate_id_from_voter)

        # Condition must be always true
        # Same candidate must be sent from co and voter
        # Hash candidate id sent from voter without the other one from CO
        candidate_id_hashed_from_voter = make_hash(candidate_id_from_voter)

        print(f"Candidate if from voter: {candidate_id_from_voter}")
        print(f"Candidate counter: {candidate.count()}")
        print(f"Candidate hash from co: {candidate_id_hashed_from_co}")
        print(f"Candidate hash(from make_hash): {candidate_id_hashed_from_voter}")
        print(f"voter_id_hashed_from_co: {voter_id_hashed_from_co}")
        print(f"voter_id_hashed_from_voter: {voter_id_hashed_from_voter}")

        # Candidate id sent from CO is sent without encyrption to prevent data size issue

        # Compare two hashes
        assert candidate.exists() and candidate_id_hashed_from_voter == candidate_id_hashed_from_co and voter_id_hashed_from_co == voter_id_hashed_from_voter, "Invalid vote"

        candidate = candidate[0]
        # If ok, add vote to the candidate
        # mark revision as done and valid

        revision.is_valid = True
        revision.done = True
        revision.save()
        candidate.save()

        # Create a new vote for the candidate
        vote = Vote.objects.create(candidate=candidate, is_valid=True)
        vote.save()

        return True
    except Exception as e:
        print(e)
        revision.done = True
        revision.is_valid = False
        revision.save()
        return None


def make_hash(clear_text):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(clear_text)
    hashed_text = digest.finalize()
    return hashed_text
