
import hashlib
import json
import secrets
from datetime import datetime, timedelta
from math import gcd, lcm

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


# =========================================================
# 1. KEY GENERATION AND SYSTEM CONFIGURATION
# =========================================================

# RSA key pair (4096 bits as specified in the question)
rsa_private = RSA.generate(4096)
rsa_public = rsa_private.publickey()

# Demonstration ElGamal signing key
# Small parameters are for lab demonstration only.
EG_P = 467
EG_G = 2
eg_private = secrets.randbelow(EG_P - 2) + 1
eg_public = pow(EG_G, eg_private, EG_P)

# Demonstration Paillier keys (same n and g as sample)
PA_P, PA_Q = 53, 59
PA_N = PA_P * PA_Q
PA_N2 = PA_N * PA_N
PA_G = PA_N + 1
PA_LAMBDA = lcm(PA_P - 1, PA_Q - 1)


def L(u):
    return (u - 1) // PA_N


PA_MU = pow(
    L(pow(PA_G, PA_LAMBDA, PA_N2)),
    -1, PA_N
)

# Voting period
START = datetime(2025, 11, 3, 9, 0, 0)
END = datetime(2025, 11, 3, 17, 0, 0)

# ballot_id -> encrypted and signed record
records = {}
paillier_votes = {}
used_voters = set()
next_ballot = 1


# =========================================================
# 2. HASHING: SHA-512
# =========================================================

def sha512(data):
    return hashlib.sha512(data).hexdigest()


# =========================================================
# 3. ELGAMAL DIGITAL SIGNATURE
# =========================================================

def sign_hash(hash_hex):
    h = int(hash_hex, 16) % (EG_P - 1)

    while True:
        k = secrets.randbelow(EG_P - 2) + 1
        if gcd(k, EG_P - 1) == 1:
            break

    r = pow(EG_G, k, EG_P)
    s = (pow(k, -1, EG_P - 1) *
         (h - eg_private * r)) % (EG_P - 1)

    return r, s


def verify_signature(hash_hex, signature):
    r, s = signature

    if not (0 < r < EG_P and 0 <= s < EG_P - 1):
        return False

    h = int(hash_hex, 16) % (EG_P - 1)

    left = (pow(eg_public, r, EG_P) *
            pow(r, s, EG_P)) % EG_P

    right = pow(EG_G, h, EG_P)

    return left == right


# =========================================================
# 4. PAILLIER HOMOMORPHIC ENCRYPTION
# =========================================================

def paillier_encrypt(message):
    if not (0 <= message < PA_N):
        raise ValueError("Candidate ID must be between 0 and n-1")

    while True:
        r = secrets.randbelow(PA_N - 1) + 1
        if gcd(r, PA_N) == 1:
            break

    c = (pow(PA_G, message, PA_N2) *
         pow(r, PA_N, PA_N2)) % PA_N2

    return c


def paillier_decrypt(ciphertext):
    u = pow(ciphertext, PA_LAMBDA, PA_N2)
    return (L(u) * PA_MU) % PA_N


def aggregate_ciphertexts(ciphertexts):
    result = 1
    for c in ciphertexts:
        result = (result * c) % PA_N2
    return result


# =========================================================
# 5. CLIENT: CAST AND ENCRYPT A BALLOT
# =========================================================

def cast_vote():
    global next_ballot

    voter_id = input("Voter ID: ").strip()

    if not voter_id:
        print("Invalid voter ID.")
        return

    if voter_id in used_voters:
        print("This voter has already voted.")
        return

    try:
        candidate = int(input("Candidate ID: "))
        constituency = input("Constituency ID: ").strip()

        if not constituency or not (0 <= candidate < PA_N):
            print("Invalid candidate or constituency.")
            return

        ballot_id = f"B{next_ballot:03d}"
        next_ballot += 1

        ballot = (
            f"CandidateID={candidate};"
            f"ConstituencyID={constituency}"
        ).encode("utf-8")

        # Hash original ballot
        digest = sha512(ballot)

        # AES-256-CBC encryption
        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(ballot, AES.block_size))

        # RSA public-key encryption of AES key
        wrapped_key = PKCS1_OAEP.new(rsa_public).encrypt(aes_key)

        # ElGamal signature of SHA-512 digest
        signature = sign_hash(digest)

        # Paillier encryption of candidate ID
        vote_ciphertext = paillier_encrypt(candidate)

        timestamp = datetime.now()

        record = {
            "ballot_id": ballot_id,
            "voter_id": voter_id,
            "constituency": constituency,
            "timestamp": timestamp,
            "iv": iv,
            "ciphertext": ciphertext,
            "wrapped_key": wrapped_key,
            "hash": digest,
            "signature": signature,
            "vote_ciphertext": vote_ciphertext,
            "status": "PENDING"
        }

        records[ballot_id] = record
        paillier_votes[ballot_id] = vote_ciphertext
        used_voters.add(voter_id)

        print("\n--- BALLOT OUTPUT ---")
        print("Ballot ID:", ballot_id)
        print("Ballot UTF-8:", ballot.decode())
        print("SHA-512:", digest)
        print("AES IV (hex):", iv.hex())
        print("AES-256-CBC ciphertext:", ciphertext.hex())
        print("RSA-wrapped AES key:", wrapped_key.hex())
        print("ElGamal signature:", signature)
        print("Paillier vote ciphertext:", hex(vote_ciphertext))
        print("Timestamp:", timestamp.strftime("%d-%m-%Y %H:%M:%S"))
        print("Output:", ballot_id, "submitted and indexed.")

    except (ValueError, OverflowError) as e:
        print("Invalid input:", e)


# =========================================================
# 6. SERVER: VERIFY AND ACCEPT BALLOT
# =========================================================

def verify_ballot():
    ballot_id = input("Ballot ID to verify: ").strip()
    record = records.get(ballot_id)

    if not record:
        print("Ballot not found.")
        return

    try:
        # Unwrap AES key using RSA private key
        aes_key = PKCS1_OAEP.new(rsa_private).decrypt(
            record["wrapped_key"]
        )

        # Decrypt ballot
        cipher = AES.new(
            aes_key, AES.MODE_CBC, record["iv"]
        )
        plaintext = unpad(
            cipher.decrypt(record["ciphertext"]),
            AES.block_size
        )

        # Recompute the ballot hash
        recomputed_hash = sha512(plaintext)

        hash_valid = recomputed_hash == record["hash"]
        signature_valid = verify_signature(
            record["hash"], record["signature"]
        )
        time_valid = START <= record["timestamp"] <= END

        print("\n--- SERVER VERIFICATION ---")
        print("RSA private-key unwrap: successful")
        print("ElGamal signature valid:", signature_valid)
        print("SHA-512 matches:", hash_valid)
        print("Timestamp within voting period:", time_valid)

        if hash_valid and signature_valid and time_valid:
            record["status"] = "ACCEPTED"
            print("Output:", ballot_id, "accepted.")
            print("Paillier vote remains encrypted.")
        else:
            record["status"] = "REJECTED"
            print("Output:", ballot_id, "rejected.")

    except (ValueError, TypeError) as e:
        record["status"] = "REJECTED"
        print("Decryption or verification failed:", e)


# =========================================================
# 7. SERVER: SEARCH ENCRYPTED RECORD INDEX
# =========================================================

def search_records():
    print("1. Search by constituency")
    print("2. Search by time range")
    choice = input("Choice: ").strip()

    if choice == "1":
        constituency = input("Constituency ID: ").strip()

        matches = [
            bid for bid, rec in records.items()
            if rec["constituency"] == constituency
        ]

    elif choice == "2":
        try:
            start_time = datetime.strptime(
                input("Start time (HH:MM): "), "%H:%M"
            ).time()
            end_time = datetime.strptime(
                input("End time (HH:MM): "), "%H:%M"
            ).time()

            matches = [
                bid for bid, rec in records.items()
                if start_time <= rec["timestamp"].time() <= end_time
            ]
        except ValueError:
            print("Invalid time format.")
            return

    else:
        print("Invalid choice.")
        return

    print("Matching ballot IDs:", matches)


# =========================================================
# 8. TALLY AUTHORITY: HOMOMORPHIC AGGREGATION
# =========================================================

def aggregate_votes():
    accepted = [
        bid for bid, rec in records.items()
        if rec["status"] == "ACCEPTED"
    ]

    if not accepted:
        print("No accepted ballots available.")
        return

    ciphertexts = [paillier_votes[bid] for bid in accepted]
    aggregate = aggregate_ciphertexts(ciphertexts)

    print("\nAccepted ballot IDs:", accepted)
    print("Aggregate ciphertext:", hex(aggregate))
    print("Only the combined ciphertext is submitted for tallying.")

    return aggregate


# =========================================================
# 9. THRESHOLD DECRYPTION DEMONSTRATION
# =========================================================

def threshold_decrypt():
    accepted = [
        bid for bid, rec in records.items()
        if rec["status"] == "ACCEPTED"
    ]

    if not accepted:
        print("No accepted votes to tally.")
        return

    # Simplified simulation: require multiple authorizations.
    # This is NOT genuine cryptographic threshold decryption.
    shares = input(
        "Enter authorizations from 3 authorities (e.g. A,B,C): "
    ).strip().split(",")

    shares = {s.strip() for s in shares if s.strip()}

    if len(shares) < 3:
        print("Insufficient authorization shares.")
        return

    aggregate = aggregate_ciphertexts(
        [paillier_votes[bid] for bid in accepted]
    )

    # Only decrypt the combined ciphertext, not individual votes.
    total = paillier_decrypt(aggregate)

    print("Threshold authorization: sufficient shares verified")
    print("Aggregate candidate-ID sum:", total)
    print("Accepted ballots:", len(accepted))
    print("Individual votes were not decrypted.")


# =========================================================
# 10. ROLE MENUS AND ACCESS CONTROL
# =========================================================

def voter_menu():
    while True:
        print("\n--- VOTER MENU ---")
        print("1. Cast vote")
        print("2. Back")

        choice = input("Choice: ").strip()

        if choice == "1":
            cast_vote()
        elif choice == "2":
            break
        else:
            print("Invalid choice.")


def server_menu():
    while True:
        print("\n--- ELECTION SERVER MENU ---")
        print("1. Verify ballot")
        print("2. Search index")
        print("3. Back")

        choice = input("Choice: ").strip()

        if choice == "1":
            verify_ballot()
        elif choice == "2":
            search_records()
        elif choice == "3":
            break
        else:
            print("Invalid choice.")


def tally_menu():
    while True:
        print("\n--- TALLY AUTHORITY MENU ---")
        print("1. Aggregate accepted votes")
        print("2. Threshold decrypt aggregate")
        print("3. Back")

        choice = input("Choice: ").strip()

        if choice == "1":
            aggregate_votes()
        elif choice == "2":
            threshold_decrypt()
        elif choice == "3":
            break
        else:
            print("Invalid choice.")


# =========================================================
# 11. MAIN MENU
# =========================================================

def main():
    while True:
        print("\n========== SECURE E-VOTING SYSTEM ==========")
        print("1. Voter")
        print("2. Election Server")
        print("3. Tally Authority")
        print("4. Exit")

        choice = input("Input Choice: ").strip()

        if choice == "1":
            voter_menu()
        elif choice == "2":
            server_menu()
        elif choice == "3":
            tally_menu()
        elif choice == "4":
            print("Exiting system.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
