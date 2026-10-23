"""Generate domain-configurable, file-based cryptography lab solutions.
Run: python generator.py
Configure record fields, exact-value searches, numeric sums, category counts,
entity names and automatic workflows. The original voting API remains available.
The source template is embedded; test.py is not needed to run this generator.
"""

from pathlib import Path
import ast
import json
import re

TEMPLATE = '# Install dependency:\n# python -m pip install pycryptodome\n#\n# File-based, menu-driven lab solution. No sockets.\n# Timestamp trust and two-authority separation are simulated locally.\n# A real deployment needs separate authority machines and a trusted time service.\n\nfrom Crypto.Cipher import AES, PKCS1_OAEP\nfrom Crypto.PublicKey import RSA, ElGamal\nfrom Crypto.Hash import SHA256\nfrom Crypto.Util.Padding import pad, unpad\nfrom Crypto.Util.number import getPrime\n\nfrom pathlib import Path\nfrom datetime import datetime, timedelta, timezone\nfrom time import perf_counter\nfrom getpass import getpass\nfrom math import gcd, lcm\n\nimport hashlib\nimport hmac\nimport json\nimport secrets\nimport os\nimport re\n\n\nBASE = Path(__file__).resolve().parent / "election_files"\nIST = timezone(timedelta(hours=5, minutes=30))\nTIME_FORMAT = "%Y-%m-%d %H:%M:%S"\n\nCANDIDATES = [1, 2, 3]\n\nROLE = None\nEVENTS = []\n\nFOLDERS = [\n    "keys",\n    "authorities",\n    "encrypted",\n    "encrypted_key",\n    "iv",\n    "hashes",\n    "signature",\n    "public_key",\n    "paillier",\n    "metadata",\n    "index",\n    "receipts",\n    "verified",\n    "tally",\n]\n\n\n# =========================================================\n# FILE STORAGE, TIMESTAMPS AND TIMINGS\n# =========================================================\n\ndef now():\n    return datetime.now(IST).strftime(TIME_FORMAT)\n\n\ndef save(folder, filename, value):\n    path = BASE / folder / filename\n    path.write_text(json.dumps(value, indent=2), encoding="utf-8")\n\n\ndef read(folder, filename):\n    path = BASE / folder / filename\n    return json.loads(path.read_text(encoding="utf-8"))\n\n\ndef ballot_filename(ballot_id):\n    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", ballot_id):\n        raise ValueError("Use a ballot ID containing letters, digits, _ or -.")\n\n    return ballot_id + ".json"\n\n\ndef require(role):\n    if ROLE != role:\n        raise PermissionError("Access denied for this role.")\n\n\ndef timed(operation, function, *args):\n    started_at = datetime.now(IST).isoformat(timespec="milliseconds")\n    start = perf_counter()\n    status = "success"\n\n    try:\n        result = function(*args)\n\n        if result is False:\n            status = "failed"\n\n        return result\n\n    except Exception:\n        status = "error"\n        raise\n\n    finally:\n        EVENTS.append({\n            "operation": operation,\n            "started_at": started_at,\n            "finished_at": datetime.now(IST).isoformat(\n                timespec="milliseconds"\n            ),\n            "duration_ms": (perf_counter() - start) * 1000,\n            "status": status,\n        })\n\n\ndef show_summary(action, details):\n    timestamp = datetime.now(IST).isoformat(timespec="milliseconds")\n\n    print(f"\\n[{timestamp}] {ROLE.upper()} - {action}")\n\n    for name, value in details.items():\n        print(name + ":", value)\n\n    totals = {}\n\n    for event in EVENTS:\n        name = event["operation"]\n        totals[name] = totals.get(name, 0) + event["duration_ms"]\n\n    if totals:\n        print(\n            "Times (ms):",\n            " | ".join(\n                f"{name}={duration:.6f}"\n                for name, duration in totals.items()\n            ),\n        )\n\n    entry = {\n        "timestamp": timestamp,\n        "role": ROLE,\n        "action": action,\n        "details": details,\n        "events": list(EVENTS),\n    }\n\n    with (BASE / "events.jsonl").open("a", encoding="utf-8") as file:\n        file.write(json.dumps(entry) + "\\n")\n\n\n# =========================================================\n# PASSWORDS AND ROLE-BASED ACCESS\n# =========================================================\n\ndef password_key(password, salt):\n    return hashlib.scrypt(\n        password.encode(),\n        salt=salt,\n        n=16384,\n        r=8,\n        p=1,\n        dklen=32,\n    )\n\n\ndef new_password(label):\n    while True:\n        password = getpass(f"Set {label} password: ")\n        confirmation = getpass("Confirm password: ")\n\n        if password and password == confirmation:\n            return password\n\n        print("Passwords must be nonempty and match.")\n\n\ndef login(role):\n    account = read("keys", "accounts.json")[role]\n    password = getpass(f"{role.capitalize()} password: ")\n\n    actual = password_key(\n        password,\n        bytes.fromhex(account["salt"]),\n    ).hex()\n\n    if not hmac.compare_digest(actual, account["hash"]):\n        print("Access denied.")\n        return False\n\n    return True\n\n\n# =========================================================\n# PASSWORD-PROTECTED THRESHOLD SHARES\n# =========================================================\n\ndef protect_share(number, share, password):\n    salt = os.urandom(16)\n    key = password_key(password, salt)\n\n    cipher = AES.new(key, AES.MODE_EAX)\n\n    ciphertext, tag = cipher.encrypt_and_digest(\n        str(share).encode()\n    )\n\n    save("authorities", f"{number}.json", {\n        "salt": salt.hex(),\n        "nonce": cipher.nonce.hex(),\n        "ciphertext": ciphertext.hex(),\n        "tag": tag.hex(),\n    })\n\n\ndef unlock_share(number, password):\n    record = read("authorities", f"{number}.json")\n\n    key = password_key(\n        password,\n        bytes.fromhex(record["salt"]),\n    )\n\n    cipher = AES.new(\n        key,\n        AES.MODE_EAX,\n        nonce=bytes.fromhex(record["nonce"]),\n    )\n\n    plaintext = cipher.decrypt_and_verify(\n        bytes.fromhex(record["ciphertext"]),\n        bytes.fromhex(record["tag"]),\n    )\n\n    return int(plaintext.decode())\n\n\n# =========================================================\n# FIRST-RUN SETUP\n# =========================================================\n\ndef setup():\n    for folder in FOLDERS:\n        (BASE / folder).mkdir(parents=True, exist_ok=True)\n\n    if (BASE / "keys" / "settings.json").exists():\n        return\n\n    if any((BASE / folder).iterdir() for folder in []):\n        pass\n\n    if any((BASE / "keys").iterdir()):\n        raise ValueError(\n            "Incomplete setup. Use a fresh election_files folder."\n        )\n\n    print("\\nFIRST-RUN ELECTION SETUP")\n    print("Enter dates in IST using YYYY-MM-DD HH:MM:SS.")\n\n    start = datetime.strptime(\n        input("Voting starts: ").strip(),\n        TIME_FORMAT,\n    )\n\n    deadline = datetime.strptime(\n        input("Voting deadline: ").strip(),\n        TIME_FORMAT,\n    )\n\n    if deadline <= start:\n        raise ValueError("Deadline must be after the starting time.")\n\n    accounts = {}\n\n    for role in ("voter", "server", "tally"):\n        password = new_password(role)\n        salt = os.urandom(16)\n\n        accounts[role] = {\n            "salt": salt.hex(),\n            "hash": password_key(password, salt).hex(),\n        }\n\n    authority_passwords = [\n        new_password("authority 1"),\n        new_password("authority 2"),\n    ]\n\n    print("Generating RSA-4096 keys...")\n\n    rsa_key = RSA.generate(4096)\n\n    save(\n        "keys",\n        "rsa_private.json",\n        rsa_key.export_key().decode(),\n    )\n\n    save(\n        "keys",\n        "rsa_public.json",\n        rsa_key.publickey().export_key().decode(),\n    )\n\n    print("Generating Paillier parameters...")\n\n    while True:\n        p = getPrime(1024)\n        q = getPrime(1024)\n\n        n = p * q\n        lam = lcm(p - 1, q - 1)\n\n        if p != q and gcd(lam, n) == 1:\n            break\n\n    # d is divisible by lambda, and d mod n = 1.\n    # Therefore L(c^d mod n²) recovers the plaintext modulo n.\n    d = lam * pow(lam, -1, n)\n    period = n * lam\n\n    share1 = secrets.randbelow(period - 1) + 1\n    share2 = (d - share1) % period\n\n    protect_share(1, share1, authority_passwords[0])\n    protect_share(2, share2, authority_passwords[1])\n\n    save("keys", "paillier_public.json", {\n        "n": n,\n        "g": n + 1,\n    })\n\n    # Do not persist p, q, lambda or the complete exponent d.\n    del p, q, lam, d, period, share1, share2\n\n    print("Generating educational ElGamal parameters...")\n\n    elgamal = ElGamal.generate(512, os.urandom)\n\n    save("keys", "elgamal.json", {\n        "p": int(elgamal.p),\n        "g": int(elgamal.g),\n    })\n\n    save("keys", "accounts.json", accounts)\n    save("keys", "search_key.json", os.urandom(32).hex())\n    save("keys", "receipt_key.json", os.urandom(32).hex())\n\n    save("keys", "settings.json", {\n        "start": start.strftime(TIME_FORMAT),\n        "deadline": deadline.strftime(TIME_FORMAT),\n        "created_at": now(),\n    })\n\n    print("Setup complete.")\n\n\n# =========================================================\n# AES-256-CBC\n# =========================================================\n\ndef aes_encrypt(plaintext, key):\n    cipher = AES.new(key, AES.MODE_CBC)\n\n    ciphertext = cipher.encrypt(\n        pad(plaintext.encode(), AES.block_size)\n    )\n\n    return cipher.iv.hex(), ciphertext.hex()\n\n\ndef aes_decrypt(ciphertext, key, iv):\n    cipher = AES.new(\n        key,\n        AES.MODE_CBC,\n        iv=bytes.fromhex(iv),\n    )\n\n    plaintext = unpad(\n        cipher.decrypt(bytes.fromhex(ciphertext)),\n        AES.block_size,\n    )\n\n    return plaintext.decode()\n\n\n# =========================================================\n# RSA-4096 KEY ENCRYPTION\n# =========================================================\n\ndef rsa_encrypt_key(key):\n    public_key = RSA.import_key(\n        read("keys", "rsa_public.json")\n    )\n\n    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)\n\n    return cipher.encrypt(key).hex()\n\n\ndef rsa_decrypt_key(ciphertext):\n    private_key = RSA.import_key(\n        read("keys", "rsa_private.json")\n    )\n\n    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)\n\n    return cipher.decrypt(bytes.fromhex(ciphertext))\n\n\n# =========================================================\n# SHA-512 AND ELGAMAL DIGITAL SIGNATURE\n# =========================================================\n\ndef hash_message(message):\n    return hashlib.sha512(message.encode()).hexdigest()\n\n\ndef generate_signing_keys():\n    parameters = read("keys", "elgamal.json")\n\n    p = parameters["p"]\n    g = parameters["g"]\n\n    private_key = secrets.randbelow(p - 2) + 1\n\n    public_key = {\n        "p": p,\n        "g": g,\n        "y": pow(g, private_key, p),\n    }\n\n    return private_key, public_key\n\n\ndef sign_hash(digest, private_key, public_key):\n    p = public_key["p"]\n    g = public_key["g"]\n\n    while True:\n        k = secrets.randbelow(p - 2) + 1\n\n        if gcd(k, p - 1) == 1:\n            break\n\n    r = pow(g, k, p)\n\n    s = (\n        (int(digest, 16) - private_key * r)\n        * pow(k, -1, p - 1)\n    ) % (p - 1)\n\n    return [r, s]\n\n\ndef signature_values(digest, signature, public_key):\n    p = public_key["p"]\n    g = public_key["g"]\n    y = public_key["y"]\n\n    r, s = signature\n\n    if not (0 < r < p and 0 <= s < p - 1):\n        raise ValueError("Invalid ElGamal signature values.")\n\n    expected = pow(g, int(digest, 16), p)\n\n    actual = (\n        pow(y, r, p) * pow(r, s, p)\n    ) % p\n\n    return expected, actual\n\n\ndef verify_signature(digest, signature, public_key):\n    expected, actual = signature_values(\n        digest, signature, public_key\n    )\n\n    return expected == actual\n\n\n# =========================================================\n# PAILLIER HOMOMORPHIC ENCRYPTION\n# =========================================================\n\ndef paillier_encrypt(message, n):\n    if not 0 <= message < n:\n        raise ValueError("Message outside Paillier range.")\n\n    while True:\n        r = secrets.randbelow(n - 1) + 1\n\n        if gcd(r, n) == 1:\n            break\n\n    ciphertext = (\n        pow(n + 1, message, n * n)\n        * pow(r, n, n * n)\n    ) % (n * n)\n\n    return ciphertext, r\n\n\n# =========================================================\n# SEARCHABLE INDEX AND LOCAL TIMESTAMP RECEIPTS\n# =========================================================\n\ndef search_token(value):\n    key = bytes.fromhex(read("keys", "search_key.json"))\n\n    return hmac.new(\n        key,\n        value.encode(),\n        hashlib.sha256,\n    ).hexdigest()\n\n\ndef seal(value):\n    key = bytes.fromhex(read("keys", "receipt_key.json"))\n\n    data = json.dumps(value, sort_keys=True).encode()\n\n    return hmac.new(\n        key,\n        data,\n        hashlib.sha256,\n    ).hexdigest()\n\n\ndef ballot_files(filename):\n    folders = [\n        "encrypted", "encrypted_key", "iv", "hashes",\n        "signature", "public_key", "paillier",\n        "metadata", "index",\n    ]\n\n    return {\n        folder: read(folder, filename)\n        for folder in folders\n    }\n\n\ndef valid_receipt(filename):\n    stored = read("receipts", filename)\n    computed = seal(ballot_files(filename))\n\n    return hmac.compare_digest(stored, computed)\n\n\n# =========================================================\n# VOTER: AUTOMATIC SUBMISSION WORKFLOW\n# =========================================================\n\ndef cast_vote(ballot_id, candidate, constituency):\n    require("voter")\n    EVENTS.clear()\n\n    filename = ballot_filename(ballot_id)\n\n    if candidate not in CANDIDATES:\n        raise ValueError("Candidate must be 1, 2 or 3.")\n\n    if not re.fullmatch(r"[0-9]+", constituency):\n        raise ValueError("Constituency must contain digits only.")\n\n    if (BASE / "metadata" / filename).exists():\n        raise ValueError("Ballot ID already exists.")\n\n    if (BASE / "tally" / "aggregate.json").exists():\n        raise ValueError("Election is already closed for tallying.")\n\n    ballot = (\n        f"CandidateID={candidate};"\n        f"ConstituencyID={constituency}"\n    )\n\n    digest = timed("Hashing", hash_message, ballot)\n\n    private_key, public_key = generate_signing_keys()\n\n    signature = timed(\n        "Signing",\n        sign_hash,\n        digest,\n        private_key,\n        public_key,\n    )\n\n    n = read("keys", "paillier_public.json")["n"]\n\n    encrypted_id, id_randomness = timed(\n        "Paillier encryption",\n        paillier_encrypt,\n        candidate,\n        n,\n    )\n\n    # Adding candidate IDs alone does not give candidate-wise counts.\n    # Encrypt a one-hot vector as well: one encrypted 1, other entries 0.\n    counts = {}\n    randomness = {}\n\n    for cid in CANDIDATES:\n        counts[str(cid)], randomness[str(cid)] = timed(\n            "Paillier encryption",\n            paillier_encrypt,\n            int(candidate == cid),\n            n,\n        )\n\n    # Randomness is encrypted alongside the ballot so the server can\n    # check Paillier consistency by re-encryption, without decrypting it.\n    payload = json.dumps({\n        "ballot": ballot,\n        "id_randomness": id_randomness,\n        "count_randomness": randomness,\n    })\n\n    aes_key = os.urandom(32)\n\n    iv, ciphertext = timed(\n        "AES encryption",\n        aes_encrypt,\n        payload,\n        aes_key,\n    )\n\n    wrapped_key = timed(\n        "RSA key encryption",\n        rsa_encrypt_key,\n        aes_key,\n    )\n\n    # The trusted local submission service assigns this timestamp.\n    timestamp = now()\n    settings = read("keys", "settings.json")\n\n    if not settings["start"] <= timestamp <= settings["deadline"]:\n        raise ValueError("Submission is outside the voting period.")\n\n    records = {\n        "encrypted": ciphertext,\n        "encrypted_key": wrapped_key,\n        "iv": iv,\n        "hashes": digest,\n        "signature": signature,\n        "public_key": public_key,\n        "paillier": {\n            "candidate_id": encrypted_id,\n            "counts": counts,\n        },\n        "metadata": {\n            "submitted_at": timestamp,\n        },\n        "index": {\n            "constituency": search_token(\n                "constituency:" + constituency\n            ),\n            "minute": search_token(\n                "minute:" + timestamp[:16]\n            ),\n        },\n    }\n\n    for folder, value in records.items():\n        save(folder, filename, value)\n\n    # Binds timestamp, ciphertext, signature, public key and vote values.\n    save("receipts", filename, seal(ballot_files(filename)))\n\n    show_summary("Cast vote", {\n        "Ballot ID": ballot_id,\n        "SHA-512": digest,\n        "ElGamal signature": signature,\n        "IV": iv,\n        "AES ciphertext": ciphertext,\n        "RSA-wrapped AES key": wrapped_key,\n        "Paillier candidate ID ciphertext": hex(encrypted_id),\n        "Submission timestamp IST": timestamp,\n        "Result": "Submitted and indexed",\n    })\n\n\n# =========================================================\n# ELECTION SERVER: AUTOMATIC VERIFICATION WORKFLOW\n# =========================================================\n\ndef verify_ballot(ballot_id):\n    require("server")\n    EVENTS.clear()\n\n    filename = ballot_filename(ballot_id)\n\n    if not valid_receipt(filename):\n        raise ValueError(\n            "Submission receipt mismatch: stored files were changed."\n        )\n\n    stored_hash = read("hashes", filename)\n    signature = read("signature", filename)\n    public_key = read("public_key", filename)\n\n    key = timed(\n        "RSA key decryption",\n        rsa_decrypt_key,\n        read("encrypted_key", filename),\n    )\n\n    plaintext = timed(\n        "AES decryption",\n        aes_decrypt,\n        read("encrypted", filename),\n        key,\n        read("iv", filename),\n    )\n\n    payload = json.loads(plaintext)\n\n    computed_hash = timed(\n        "Hashing",\n        hash_message,\n        payload["ballot"],\n    )\n\n    hash_valid = timed(\n        "Hash verification",\n        hmac.compare_digest,\n        stored_hash,\n        computed_hash,\n    )\n\n    signature_valid = timed(\n        "Signature verification",\n        verify_signature,\n        computed_hash,\n        signature,\n        public_key,\n    )\n\n    expected, actual = signature_values(\n        computed_hash,\n        signature,\n        public_key,\n    )\n\n    timestamp = read("metadata", filename)["submitted_at"]\n    settings = read("keys", "settings.json")\n\n    datetime.strptime(timestamp, TIME_FORMAT)\n\n    timestamp_valid = (\n        settings["start"] <= timestamp <= settings["deadline"]\n        and timestamp <= now()\n    )\n\n    details = {\n        "Ballot ID": ballot_id,\n        "Stored SHA-512": stored_hash,\n        "Computed SHA-512": computed_hash,\n        "Hash comparison": "MATCH" if hash_valid else "MISMATCH",\n        "ElGamal signature": signature,\n        "Expected verification value": expected,\n        "Actual verification value": actual,\n        "Signature comparison": (\n            "MATCH" if signature_valid else "MISMATCH"\n        ),\n        "Submission timestamp IST": timestamp,\n        "Timestamp valid": timestamp_valid,\n    }\n\n    if not (hash_valid and signature_valid and timestamp_valid):\n        details["Result"] = "REJECTED"\n        show_summary("Verify ballot", details)\n        return False\n\n    match = re.fullmatch(\n        r"CandidateID=([0-9]+);ConstituencyID=([0-9]+)",\n        payload["ballot"],\n    )\n\n    if not match:\n        raise ValueError("Invalid ballot format.")\n\n    candidate = int(match.group(1))\n    constituency = match.group(2)\n\n    if candidate not in CANDIDATES:\n        raise ValueError("Invalid candidate.")\n\n    n = read("keys", "paillier_public.json")["n"]\n    encrypted = read("paillier", filename)\n\n    checks = [\n        (\n            candidate,\n            payload["id_randomness"],\n            encrypted["candidate_id"],\n        )\n    ]\n\n    for cid in CANDIDATES:\n        checks.append((\n            int(candidate == cid),\n            payload["count_randomness"][str(cid)],\n            encrypted["counts"][str(cid)],\n        ))\n\n    for message, randomness, ciphertext in checks:\n        if not 0 < randomness < n or gcd(randomness, n) != 1:\n            raise ValueError("Invalid Paillier randomness.")\n\n        expected_ciphertext = (\n            pow(n + 1, message, n * n)\n            * pow(randomness, n, n * n)\n        ) % (n * n)\n\n        if ciphertext != expected_ciphertext:\n            raise ValueError(\n                "Paillier ciphertext does not match the signed ballot."\n            )\n\n    expected_index = {\n        "constituency": search_token(\n            "constituency:" + constituency\n        ),\n        "minute": search_token(\n            "minute:" + timestamp[:16]\n        ),\n    }\n\n    if read("index", filename) != expected_index:\n        raise ValueError("Search index mismatch.")\n\n    save("verified", filename, {\n        "verified_at": now(),\n        "receipt": read("receipts", filename),\n    })\n\n    details["Result"] = "ACCEPTED; Paillier values remain encrypted"\n    show_summary("Verify ballot", details)\n\n    return True\n\n\n# =========================================================\n# SERVER SEARCH: NO BALLOT DECRYPTION\n# =========================================================\n\ndef search_ballots():\n    require("server")\n    EVENTS.clear()\n\n    print("\\n1. Search by constituency")\n    print("2. Search by time range")\n\n    choice = input("Enter choice: ").strip()\n\n    if choice == "1":\n        constituency = input("Constituency ID: ").strip()\n        tokens = {search_token("constituency:" + constituency)}\n        field = "constituency"\n        start = end = None\n\n    elif choice == "2":\n        print("Use YYYY-MM-DD HH:MM:SS in IST.")\n\n        start = datetime.strptime(\n            input("Start: ").strip(), TIME_FORMAT\n        )\n\n        end = datetime.strptime(\n            input("End: ").strip(), TIME_FORMAT\n        )\n\n        if end < start or end - start > timedelta(days=7):\n            raise ValueError("Use an ordered range of at most 7 days.")\n\n        tokens = set()\n        minute = start.replace(second=0)\n\n        while minute <= end:\n            tokens.add(search_token(\n                "minute:" + minute.strftime("%Y-%m-%d %H:%M")\n            ))\n            minute += timedelta(minutes=1)\n\n        field = "minute"\n\n    else:\n        raise ValueError("Invalid search choice.")\n\n    matches = []\n\n    for file in sorted((BASE / "index").glob("*.json")):\n        if not valid_receipt(file.name):\n            continue\n\n        index = read("index", file.name)\n\n        if index[field] not in tokens:\n            continue\n\n        if start is not None:\n            timestamp = datetime.strptime(\n                read("metadata", file.name)["submitted_at"],\n                TIME_FORMAT,\n            )\n\n            if not start <= timestamp <= end:\n                continue\n\n        matches.append(file.stem)\n\n    show_summary("Search index", {\n        "Matching ballot IDs": matches,\n    })\n\n\n# =========================================================\n# HOMOMORPHIC AGGREGATION\n# =========================================================\n\ndef build_aggregate():\n    n = read("keys", "paillier_public.json")["n"]\n\n    totals = {\n        "candidate_id_sum": 1,\n        **{str(cid): 1 for cid in CANDIDATES},\n    }\n\n    receipts = {}\n\n    for file in sorted((BASE / "verified").glob("*.json")):\n        if not valid_receipt(file.name):\n            raise ValueError("Accepted ballot changed: " + file.stem)\n\n        verified = read("verified", file.name)\n        receipt = read("receipts", file.name)\n\n        if verified["receipt"] != receipt:\n            raise ValueError("Ballot needs verification again.")\n\n        receipts[file.stem] = receipt\n        encrypted = read("paillier", file.name)\n\n        totals["candidate_id_sum"] = (\n            totals["candidate_id_sum"] * encrypted["candidate_id"]\n        ) % (n * n)\n\n        for cid in CANDIDATES:\n            totals[str(cid)] = (\n                totals[str(cid)] * encrypted["counts"][str(cid)]\n            ) % (n * n)\n\n    submitted = len(list((BASE / "receipts").glob("*.json")))\n\n    if len(receipts) < 2:\n        raise ValueError("Verify at least two ballots before tallying.")\n\n    if len(receipts) != submitted:\n        raise ValueError("Verify every submitted ballot first.")\n\n    if len(receipts) * max(CANDIDATES) >= n:\n        raise ValueError("Vote total exceeds the Paillier range.")\n\n    return {\n        "ciphertexts": totals,\n        "ballots": receipts,\n    }\n\n\ndef aggregate_votes():\n    require("tally")\n    EVENTS.clear()\n\n    aggregate = timed(\n        "Homomorphic aggregation",\n        build_aggregate,\n    )\n\n    save("tally", "aggregate.json", aggregate)\n    save("tally", "aggregate_seal.json", seal(aggregate))\n\n    show_summary("Aggregate votes", {\n        "Included ballots": list(aggregate["ballots"]),\n        "Aggregate ciphertexts": aggregate["ciphertexts"],\n        "Result": "Election closed; no Paillier votes decrypted",\n    })\n\n\n# =========================================================\n# TWO-OF-TWO AGGREGATE DECRYPTION\n# =========================================================\n\ndef threshold_decrypt():\n    require("tally")\n    EVENTS.clear()\n\n    aggregate = read("tally", "aggregate.json")\n    stored_seal = read("tally", "aggregate_seal.json")\n\n    if not hmac.compare_digest(seal(aggregate), stored_seal):\n        raise ValueError("Aggregate was changed.")\n\n    if aggregate != build_aggregate():\n        raise ValueError("Aggregate is stale.")\n\n    n = read("keys", "paillier_public.json")["n"]\n    partials = []\n\n    # Only the sealed aggregate is accepted here.\n    # There is no menu for decrypting an individual Paillier vote.\n    for number in (1, 2):\n        password = getpass(f"Authority {number} password: ")\n\n        share = timed(\n            f"Authority {number} authentication",\n            unlock_share,\n            number,\n            password,\n        )\n\n        partial = {}\n\n        for name, ciphertext in aggregate["ciphertexts"].items():\n            partial[name] = timed(\n                f"Authority {number} partial decryption",\n                pow,\n                ciphertext,\n                share,\n                n * n,\n            )\n\n        save("tally", f"partial_{number}.json", {\n            "created_at": now(),\n            "aggregate_seal": stored_seal,\n            "values": partial,\n        })\n\n        partials.append(partial)\n        del share\n\n    results = {}\n\n    for name in aggregate["ciphertexts"]:\n        combined = (\n            partials[0][name] * partials[1][name]\n        ) % (n * n)\n\n        if (combined - 1) % n != 0:\n            raise ValueError("Invalid combined partial decryption.")\n\n        results[name] = ((combined - 1) // n) % n\n\n    vote_count = len(aggregate["ballots"])\n\n    if sum(results[str(cid)] for cid in CANDIDATES) != vote_count:\n        raise ValueError("Candidate counts do not match ballot count.")\n\n    expected_id_sum = sum(\n        cid * results[str(cid)] for cid in CANDIDATES\n    )\n\n    if results["candidate_id_sum"] != expected_id_sum:\n        raise ValueError("Candidate-ID sum is inconsistent.")\n\n    save("tally", "final_totals.json", {\n        "completed_at": now(),\n        "results": results,\n    })\n\n    details = {\n        f"Candidate {cid} count": results[str(cid)]\n        for cid in CANDIDATES\n    }\n\n    details["Total votes"] = vote_count\n    details["Candidate ID sum"] = results["candidate_id_sum"]\n    details["Result"] = "Only aggregate Paillier values decrypted"\n\n    show_summary("Threshold decryption", details)\n\n\n# =========================================================\n# VOTER MENU\n# =========================================================\n\ndef voter():\n    require("voter")\n\n    while True:\n        print("\\n------ VOTER MENU ------")\n        print("1. Cast vote")\n        print("2. Back")\n\n        choice = input("Enter choice: ").strip()\n\n        if choice == "1":\n            ballot_id = input("Ballot ID: ").strip()\n            candidate = int(input("Candidate ID (1, 2, 3): "))\n            constituency = input("Constituency ID: ").strip()\n\n            cast_vote(ballot_id, candidate, constituency)\n\n        elif choice == "2":\n            break\n\n        else:\n            print("Invalid choice.")\n\n\n# =========================================================\n# ELECTION SERVER MENU\n# =========================================================\n\ndef election_server():\n    require("server")\n\n    while True:\n        print("\\n------ ELECTION SERVER MENU ------")\n        print("1. Verify ballot")\n        print("2. Search index")\n        print("3. Back")\n\n        choice = input("Enter choice: ").strip()\n\n        if choice == "1":\n            verify_ballot(input("Ballot ID: ").strip())\n\n        elif choice == "2":\n            search_ballots()\n\n        elif choice == "3":\n            break\n\n        else:\n            print("Invalid choice.")\n\n\n# =========================================================\n# TALLY AUTHORITY MENU\n# =========================================================\n\ndef tally_authority():\n    require("tally")\n\n    while True:\n        print("\\n------ TALLY AUTHORITY MENU ------")\n        print("1. Aggregate votes and close election")\n        print("2. Threshold decrypt aggregate")\n        print("3. Back")\n\n        choice = input("Enter choice: ").strip()\n\n        if choice == "1":\n            aggregate_votes()\n\n        elif choice == "2":\n            threshold_decrypt()\n\n        elif choice == "3":\n            break\n\n        else:\n            print("Invalid choice.")\n\n\n# =========================================================\n# MAIN MENU\n# =========================================================\n\ndef main():\n    global ROLE\n\n    setup()\n\n    handlers = {\n        "1": ("voter", voter),\n        "2": ("server", election_server),\n        "3": ("tally", tally_authority),\n    }\n\n    while True:\n        print("\\n" + "=" * 45)\n        print("       SECURE ELECTRONIC VOTING")\n        print("=" * 45)\n        print("1. Voter")\n        print("2. Election Server")\n        print("3. Tally Authority")\n        print("4. Exit")\n\n        choice = input("Enter choice: ").strip()\n\n        if choice == "4":\n            print("Exiting system.")\n            break\n\n        if choice not in handlers:\n            print("Invalid choice.")\n            continue\n\n        role, handler = handlers[choice]\n\n        try:\n            if login(role):\n                ROLE = role\n                handler()\n\n        except (\n            OSError,\n            ValueError,\n            KeyError,\n            TypeError,\n            IndexError,\n            PermissionError,\n        ) as error:\n            print("Operation stopped:", error)\n\n        finally:\n            ROLE = None\n\n\n# =========================================================\n# PROGRAM START\n# =========================================================\n\nif __name__ == "__main__":\n    try:\n        main()\n    except (KeyboardInterrupt, EOFError):\n        print("\\nProgram closed.")'

ACTIONS = {
    "cast_vote": "Cast vote: SHA-512, ElGamal signing, AES-256, RSA-4096, Paillier, timestamp and index",
    "verify_ballot": "Verify ballot: decrypt key/ballot, compare hash/signature, check timestamp and vote consistency",
    "search_ballots": "Search by constituency or time range",
    "aggregate_votes": "Aggregate accepted votes and close election",
    "threshold_decrypt": "Decrypt aggregate using both authority passwords",
}

REQUIREMENTS = {
    "cast_vote": "voter",
    "verify_ballot": "server",
    "search_ballots": "server",
    "aggregate_votes": "tally",
    "threshold_decrypt": "tally",
}

ENTITY_RUNTIME = r'''
def entity_menu(entity):
    if ROLE != entity or entity not in ENTITIES:
        raise PermissionError("Access denied for this entity.")
    while True:
        print("\n------ " + entity.upper() + " ------")
        print("Assigned workflow:")
        for action in ENTITIES[entity]:
            print(" - " + ENTITY_ACTIONS[action])
        print("1. Run assigned workflow")
        print("2. Back")
        choice = input("Enter choice: ").strip()
        if choice == "2":
            return
        if choice != "1":
            print("Invalid choice.")
            continue
        selected = ENTITIES[entity]
        if not selected:
            print("This entity has no assigned operations.")
            continue
        ballot_id = None
        if "cast_vote" in selected or "verify_ballot" in selected:
            ballot_id = input("Ballot ID: ").strip()
            ballot_filename(ballot_id)
        # Reuse one ballot ID across submission and verification.
        # The underlying workflows and all their checks remain unchanged.
        for action in ENTITY_ACTIONS:
            if action not in selected:
                continue
            if action == "cast_vote":
                candidate = int(input("Candidate ID (1, 2, 3): "))
                constituency = input("Constituency ID: ").strip()
                cast_vote(ballot_id, candidate, constituency)
            elif action == "verify_ballot":
                if not verify_ballot(ballot_id):
                    print("Workflow stopped: ballot verification failed.")
                    break
            elif action == "search_ballots":
                search_ballots()
            elif action == "aggregate_votes":
                aggregate_votes()
            elif action == "threshold_decrypt":
                threshold_decrypt()


def main():
    global ROLE
    setup()
    names = list(ENTITIES)
    while True:
        print("\n" + "=" * 45)
        print("       SECURE ELECTRONIC VOTING")
        print("=" * 45)
        for number, entity in enumerate(names, 1):
            print(f"{number}. {entity}")
        print(f"{len(names) + 1}. Exit")
        choice = input("Enter choice: ").strip()
        if choice == str(len(names) + 1):
            print("Exiting system.")
            break
        if not choice.isdigit() or not 1 <= int(choice) <= len(names):
            print("Invalid choice.")
            continue
        entity = names[int(choice) - 1]
        try:
            if login(entity):
                ROLE = entity
                entity_menu(entity)
        except (OSError, ValueError, KeyError, TypeError, IndexError, PermissionError) as error:
            print("Operation stopped:", error)
        finally:
            ROLE = None
'''


def validate_entities(entities, actions=None):
    available = ACTIONS if actions is None else actions
    if not isinstance(entities, dict) or not entities:
        raise ValueError("Configure at least one entity.")
    validated = {}
    seen = set()
    for name, actions in entities.items():
        if not isinstance(name, str) or not name.strip() or any(ord(c) < 32 for c in name):
            raise ValueError("Entity names must be nonempty text without control characters.")
        name = name.strip()
        if name.casefold() in seen:
            raise ValueError("Entity names must be unique, ignoring case.")
        seen.add(name.casefold())
        if not isinstance(actions, (list, tuple, set)) or any(a not in available for a in actions):
            raise ValueError("Use only the available workflow permissions.")
        validated[name] = [action for action in available if action in actions]
    return validated


def build_source(entities):
    entities = validate_entities(entities)
    tree = ast.parse(TEMPLATE)
    changes = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        original = ast.get_source_segment(TEMPLATE, node)
        replacement = original
        if node.name == "require":
            replacement = '''def require(action):
    if ROLE not in ENTITIES or action not in ENTITIES[ROLE]:
        raise PermissionError("This entity is not allowed to perform " + action + ".")'''
        elif node.name == "setup":
            before = 'for role in ("voter", "server", "tally"):'
            if before not in original:
                raise ValueError("Unexpected account setup template.")
            replacement = original.replace(before, 'for role in ENTITIES:', 1)
        elif node.name in REQUIREMENTS:
            before = 'require("' + REQUIREMENTS[node.name] + '")'
            if before not in original:
                raise ValueError("Unexpected permission check for " + node.name)
            replacement = original.replace(before, 'require("' + node.name + '")', 1)
        elif node.name in ("voter", "election_server", "tally_authority"):
            replacement = ''
        elif node.name == "main":
            replacement = ENTITY_RUNTIME.strip()
        if replacement != original:
            changes.append((node.lineno - 1, node.end_lineno, replacement + '\n'))
    lines = TEMPLATE.splitlines(keepends=True)
    for start, end, replacement in reversed(changes):
        lines[start:end] = [replacement]
    source = ''.join(lines)
    source = source.replace('ROLE = None',
        'ENTITIES = ' + repr(entities) + '\nENTITY_ACTIONS = ' + repr(ACTIONS) + '\n\nROLE = None', 1)
    ast.parse(source)
    return source, entities


def create_solution(entities, output_dir):
    source, entities = build_source(entities)
    directory = Path(output_dir).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'solution.py').write_text(source, encoding='utf-8')
    (directory / 'entities.json').write_text(json.dumps(entities, indent=2, ensure_ascii=False), encoding='utf-8')
    (directory / 'requirements.txt').write_text('pycryptodome\n', encoding='utf-8')
    (directory / '.gitignore').write_text('election_files/\n__pycache__/\n*.py[cod]\n', encoding='utf-8')
    (directory / 'RUN.txt').write_text(
        'Run python -m pip install -r requirements.txt, then python solution.py.\n\n'
        'First run: enter the voting period, set each entity password, and set\n'
        'the two independent authority passwords. Password input is hidden.\n'
        'Log in as an entity and choose Run assigned workflow. Its selected\n'
        'functions run in voting order, with one ballot ID shared where needed.\n'
        'Submission includes hashing, signing and encryption automatically.\n'
        'Verification includes the original comparison and timing outputs.\n'
        'Search still asks for constituency/time range. Aggregation still\n'
        'requires every submitted ballot verified and at least two ballots.\n'
        'Threshold decryption still needs BOTH original authority passwords.\n'
        'Custom entity names do not remove the two-authority requirement.\n'
        'Changing entity permissions requires generating a fresh solution.\n'
        'The embedded ENTITIES policy controls permissions; entities.json is\n'
        'a readable copy. No existing voting files are overwritten.\n\n'
        'The original local-demo trust model, crypto, storage and passwords\n'
        'are unchanged. No sockets. No uploads or pushes.\n', encoding='utf-8')
    return directory / 'solution.py'


def choose_entities(actions=None):
    actions = ACTIONS if actions is None else actions
    while True:
        value = input('Number of entities: ').strip()
        if value.isdigit() and 1 <= int(value) <= 100:
            count = int(value)
            break
        print('Enter a number from 1 to 100.')
    entities = {}
    names = list(actions)
    for number in range(1, count + 1):
        while True:
            name = input(f'Name of entity {number}: ').strip()
            if name and not any(ord(c) < 32 for c in name) and name.casefold() not in {n.casefold() for n in entities}:
                break
            print('Enter a unique nonempty entity name.')
        print('\nChoose complete workflows for ' + name + ':')
        for index, action in enumerate(names, 1):
            print(f'{index}. {actions[action]}')
        while True:
            answer = input('Allowed workflows (comma-separated numbers, all, or none): ').strip().lower()
            try:
                if answer == 'all':
                    selected = names[:]
                elif answer == 'none':
                    selected = []
                else:
                    selected = []
                    for item in answer.split(','):
                        item = item.strip()
                        if item.isdigit() and 1 <= int(item) <= len(names):
                            item = names[int(item) - 1]
                        if item not in actions:
                            raise ValueError('Unknown workflow: ' + item)
                        selected.append(item)
                entities.update(validate_entities({name: selected}, actions))
                break
            except ValueError as error:
                print(error)
    unassigned = set(actions) - {a for permissions in entities.values() for a in permissions}
    if unassigned:
        print('Unassigned workflows:', ', '.join(sorted(unassigned)))
        print('These functions will not be available to any entity.')
    return entities


def voting_main():
    print('VOTING SOLUTION GENERATOR')
    print('Only entity names, account names and workflow permissions are configurable.')
    print('The original voting cryptography and behavior remain unchanged.')
    entities = choose_entities()
    for name, permissions in entities.items():
        print(name + ': ' + (', '.join(permissions) or 'none'))
    default = Path(__file__).resolve().parent / 'generated_voting_solution'
    while True:
        answer = input(f'NEW output folder (Enter for {default}): ').strip()
        try:
            output = create_solution(entities, Path(answer).expanduser() if answer else default)
            break
        except FileExistsError:
            print('Folder already exists. Choose a new folder to preserve its election files.')
        except (OSError, ValueError) as error:
            print('Could not create solution:', error)
    print('Created:', output)
    print('Open that folder and run: python solution.py')


DOMAIN_ACTIONS = {
    "submit_record": "Submit record: hash, sign, encrypt, protect key, encrypt totals and index",
    "verify_record": "Verify record: decrypt internally, compare hashes/signature and validate metadata",
    "view_record": "Verify and display plaintext record",
    "search_records": "Search configured fields or submission time (IDs only)",
    "aggregate_records": "Aggregate all verified encrypted totals and category counts",
    "threshold_decrypt": "Decrypt aggregate using both authority passwords",
}

DOMAIN_RUNTIME = r'''
from decimal import Decimal, InvalidOperation


def record_filename(record_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", record_id):
        raise ValueError("Record ID must contain 1..40 letters, digits, underscores or hyphens.")
    return record_id + ".json"


def require(action):
    if ROLE not in ENTITIES or action not in ENTITIES[ROLE]:
        raise PermissionError("This entity cannot perform " + action)


def normalize_record(values):
    if set(values) != {field["name"] for field in DOMAIN["fields"]}:
        raise ValueError("Record fields do not match the configured schema.")
    result = {}
    for field in DOMAIN["fields"]:
        name, kind = field["name"], field["type"]
        value = str(values[name]).strip()
        if not value:
            raise ValueError(name + " cannot be empty.")
        if kind == "text":
            result[name] = value
        elif kind == "choice":
            matches = [option for option in field["choices"] if option.casefold() == value.casefold()]
            if not matches:
                raise ValueError(name + ": choose " + ", ".join(field["choices"]))
            result[name] = matches[0]
        else:
            if len(value) > 80 or not re.fullmatch(r"[+]?[0-9]+(?:[.][0-9]+)?", value):
                raise ValueError(name + ": use nonnegative digits with an optional decimal point (no exponent notation).")
            try:
                number = Decimal(value)
                scale = field.get("decimals", 0)
                if not number.is_finite() or number < 0 or number > Decimal(10**18) / (10**scale):
                    raise ValueError(name + ": use a finite nonnegative number within the allowed range.")
                units = number * (10**scale)
                if units != units.to_integral_value():
                    raise ValueError(name + f": use at most {scale} decimal places.")
                result[name] = int(number) if kind == "integer" else format(number, f".{scale}f")
            except InvalidOperation as exc:
                raise ValueError(name + ": invalid number.") from exc
    return result


def metric_values(record):
    values = {}
    for name, metric in METRICS.items():
        if metric["kind"] == "record_count":
            values[name] = 1
        elif metric["kind"] == "count":
            values[name] = int(record[metric["field"]] == metric["choice"])
        else:
            values[name] = int(Decimal(str(record[metric["field"]])) * metric["scale"])
    return values


def make_index(record, timestamp):
    result = {field["name"]: search_token(field["name"] + ":" + str(record[field["name"]]).casefold())
              for field in DOMAIN["fields"] if field["search"]}
    result["__minute__"] = search_token("minute:" + timestamp[:16])
    return result


def record_files(filename):
    return {folder: read(folder, filename) for folder in (
        "encrypted", "encrypted_key", "iv", "hashes", "signature",
        "public_key", "paillier", "metadata", "index")}


def valid_receipt(filename):
    return hmac.compare_digest(read("receipts", filename), seal(record_files(filename)))


def submit_record(record_id, values):
    require("submit_record")
    EVENTS.clear()
    filename = record_filename(record_id)
    if (BASE / "metadata" / filename).exists():
        raise ValueError("Record ID already exists; use a new ID for a new record.")
    if DOMAIN["close_on_aggregate"] and (BASE / "tally" / "aggregate.json").exists():
        raise ValueError("Submissions closed when the aggregate was created.")
    record = normalize_record(values)
    serialized = json.dumps(record, sort_keys=True, ensure_ascii=False)
    digest = timed("Hashing", hash_message, serialized)
    private_key, public_key = generate_signing_keys()
    signature = timed("Signing", sign_hash, digest, private_key, public_key)
    n = read("keys", "paillier_public.json")["n"]
    encrypted, randomness = {}, {}
    for name, value in metric_values(record).items():
        encrypted[name], randomness[name] = timed("Paillier encryption", paillier_encrypt, value, n)
    payload = json.dumps({"record": record, "randomness": randomness}, ensure_ascii=False)
    key = os.urandom(32)
    iv, ciphertext = timed("AES encryption", aes_encrypt, payload, key)
    wrapped = timed("RSA key encryption", rsa_encrypt_key, key)
    timestamp = now()
    settings = read("keys", "settings.json")
    if not settings["start"] <= timestamp <= settings["deadline"]:
        raise ValueError("Outside the submission period.")
    files = {"encrypted": ciphertext, "encrypted_key": wrapped, "iv": iv,
             "hashes": digest, "signature": signature, "public_key": public_key,
             "paillier": encrypted, "metadata": {"submitted_at": timestamp},
             "index": make_index(record, timestamp)}
    for folder, value in files.items():
        save(folder, filename, value)
    save("receipts", filename, seal(record_files(filename)))
    show_summary("Submit " + DOMAIN["record_name"], {"Record ID": record_id,
        "SHA-512": digest, "ElGamal signature": signature, "IV": iv,
        "AES ciphertext": ciphertext, "RSA-wrapped key": wrapped,
        "Encrypted totals": encrypted, "Submitted at IST": timestamp, "Result": "SUBMITTED"})
    return True


def check_record(record_id):
    # Internal verification pipeline; exposed only through permission-checked functions.
    filename = record_filename(record_id)
    if not valid_receipt(filename):
        raise ValueError("Receipt mismatch: stored record or metadata was changed.")
    stored_hash = read("hashes", filename)
    signature = read("signature", filename)
    public_key = read("public_key", filename)
    key = timed("RSA key decryption", rsa_decrypt_key, read("encrypted_key", filename))
    payload = json.loads(timed("AES decryption", aes_decrypt, read("encrypted", filename), key, read("iv", filename)))
    record = normalize_record(payload["record"])
    serialized = json.dumps(record, sort_keys=True, ensure_ascii=False)
    computed_hash = timed("Hashing", hash_message, serialized)
    hash_valid = timed("Hash verification", hmac.compare_digest, stored_hash, computed_hash)
    signature_valid = timed("Signature verification", verify_signature, computed_hash, signature, public_key)
    expected, actual = signature_values(computed_hash, signature, public_key)
    timestamp = read("metadata", filename)["submitted_at"]
    datetime.strptime(timestamp, TIME_FORMAT)
    settings = read("keys", "settings.json")
    valid_time = settings["start"] <= timestamp <= settings["deadline"] and timestamp <= now()
    details = {"Record ID": record_id, "Stored SHA-512": stored_hash, "Computed SHA-512": computed_hash,
               "Hash comparison": "MATCH" if hash_valid else "MISMATCH", "ElGamal signature": signature,
               "Expected verification value": expected, "Actual verification value": actual,
               "Signature comparison": "MATCH" if signature_valid else "MISMATCH", "Timestamp valid": valid_time}
    if not (hash_valid and signature_valid and valid_time):
        show_summary("Verify " + DOMAIN["record_name"], {**details, "Result": "REJECTED"})
        raise ValueError("Verification failed.")
    n = read("keys", "paillier_public.json")["n"]
    encrypted = read("paillier", filename)
    if set(encrypted) != set(METRICS) or set(payload["randomness"]) != set(METRICS):
        raise ValueError("Encrypted metric schema mismatch.")
    for name, value in metric_values(record).items():
        r = payload["randomness"][name]
        if not 0 < r < n or gcd(r, n) != 1:
            raise ValueError("Invalid Paillier randomness.")
        if encrypted[name] != pow(n + 1, value, n*n) * pow(r, n, n*n) % (n*n):
            raise ValueError("Encrypted total does not match the signed record.")
    if read("index", filename) != make_index(record, timestamp):
        raise ValueError("Search index mismatch.")
    return record, details


def verify_record(record_id):
    require("verify_record")
    EVENTS.clear()
    _, details = check_record(record_id)
    filename = record_filename(record_id)
    save("verified", filename, {"verified_at": now(), "receipt": read("receipts", filename)})
    show_summary("Verify " + DOMAIN["record_name"], {**details, "Result": "ACCEPTED"})
    return True


def view_record(record_id):
    require("view_record")
    EVENTS.clear()
    record, details = check_record(record_id)
    show_summary("Read " + DOMAIN["record_name"], {**details, "Result": "Verified before display"})
    print("Plaintext record:")
    for field in DOMAIN["fields"]:
        print(field["name"] + ":", record[field["name"]])
    return record


def find_records(field_name=None, query=None, start=None, end=None):
    require("search_records")
    EVENTS.clear()
    tokens = set()
    if field_name is not None:
        field = next((f for f in DOMAIN["fields"] if f["name"] == field_name and f["search"]), None)
        if field is None:
            raise ValueError("This field is not searchable.")
        if field["type"] == "integer":
            query = str(int(query))
        elif field["type"] == "decimal":
            number = Decimal(str(query))
            if not number.is_finite() or number * 10**field["decimals"] != (number * 10**field["decimals"]).to_integral_value():
                raise ValueError("Invalid decimal query precision.")
            query = format(number, f".{field['decimals']}f")
        tokens.add(search_token(field_name + ":" + str(query).strip().casefold()))
        index_field = field_name
    else:
        start_time = datetime.strptime(start, TIME_FORMAT)
        end_time = datetime.strptime(end, TIME_FORMAT)
        if end_time < start_time or end_time - start_time > timedelta(days=7):
            raise ValueError("Use an ordered time range of at most seven days.")
        minute = start_time.replace(second=0)
        while minute <= end_time:
            tokens.add(search_token("minute:" + minute.strftime("%Y-%m-%d %H:%M")))
            minute += timedelta(minutes=1)
        index_field = "__minute__"
    matches = []
    for file in sorted((BASE / "index").glob("*.json")):
        if not valid_receipt(file.name):
            continue
        if read("index", file.name).get(index_field) not in tokens:
            continue
        if field_name is None:
            timestamp = datetime.strptime(read("metadata", file.name)["submitted_at"], TIME_FORMAT)
            if not start_time <= timestamp <= end_time:
                continue
        matches.append(file.stem)
    show_summary("Search", {"Matching record IDs": matches})
    return matches


def search_records():
    require("search_records")
    fields = [f for f in DOMAIN["fields"] if f["search"]]
    for number, field in enumerate(fields, 1):
        print(f"{number}. {field['name']}")
    print(f"{len(fields)+1}. Submission time range")
    choice = int(input("Search by: "))
    if 1 <= choice <= len(fields):
        field = fields[choice-1]
        return find_records(field["name"], input("Exact value: "))
    if choice == len(fields)+1:
        print("Use YYYY-MM-DD HH:MM:SS, IST.")
        return find_records(start=input("Start: ").strip(), end=input("End: ").strip())
    raise ValueError("Invalid search selection.")


def build_aggregate():
    n = read("keys", "paillier_public.json")["n"]
    totals = {name: 1 for name in METRICS}
    receipts = {}
    for file in sorted((BASE / "verified").glob("*.json")):
        if not valid_receipt(file.name):
            raise ValueError("Accepted record changed: " + file.stem)
        receipt = read("receipts", file.name)
        if read("verified", file.name)["receipt"] != receipt:
            raise ValueError("Record must be verified again.")
        receipts[file.stem] = receipt
        encrypted = read("paillier", file.name)
        if set(encrypted) != set(METRICS):
            raise ValueError("Metric schema mismatch.")
        for name in METRICS:
            totals[name] = totals[name] * encrypted[name] % (n*n)
    count = len(receipts)
    if count < DOMAIN["min_records"]:
        raise ValueError(f"Verify at least {DOMAIN['min_records']} records first.")
    if count != len(list((BASE / "receipts").glob("*.json"))):
        raise ValueError("Every submitted record must be verified before aggregation.")
    if count * 10**18 >= n:
        raise ValueError("Aggregate could overflow the Paillier plaintext range.")
    return {"ciphertexts": totals, "records": receipts}


def aggregate_records():
    require("aggregate_records")
    EVENTS.clear()
    aggregate = timed("Homomorphic aggregation", build_aggregate)
    save("tally", "aggregate.json", aggregate)
    save("tally", "aggregate_seal.json", seal(aggregate))
    show_summary("Aggregate", {"Included record IDs": list(aggregate["records"]),
                              "Encrypted totals": aggregate["ciphertexts"],
                              "Submissions closed": DOMAIN["close_on_aggregate"]})
    return aggregate


def threshold_decrypt():
    require("threshold_decrypt")
    EVENTS.clear()
    aggregate = read("tally", "aggregate.json")
    aggregate_seal = read("tally", "aggregate_seal.json")
    if not hmac.compare_digest(seal(aggregate), aggregate_seal):
        raise ValueError("Aggregate was changed.")
    if aggregate != build_aggregate():
        raise ValueError("Aggregate is stale. Re-aggregate all verified records.")
    n = read("keys", "paillier_public.json")["n"]
    partials = []
    for number in (1, 2):
        share = timed(f"Authority {number} authentication", unlock_share, number,
                      getpass(f"Authority {number} password: "))
        partial = {name: timed(f"Authority {number} partial decryption", pow, value, share, n*n)
                   for name, value in aggregate["ciphertexts"].items()}
        save("tally", f"partial_{number}.json", {"created_at": now(), "aggregate_seal": aggregate_seal, "values": partial})
        partials.append(partial)
        del share
    raw_results, results = {}, {}
    for name, metric in METRICS.items():
        combined = partials[0][name] * partials[1][name] % (n*n)
        if (combined-1) % n:
            raise ValueError("Invalid combined partial decryption.")
        value = ((combined-1)//n) % n
        raw_results[name] = value
        results[metric["label"]] = (format(Decimal(value) / metric["scale"], f".{metric['decimals']}f")
                                   if metric["scale"] != 1 else value)
    if raw_results["record_count"] != len(aggregate["records"]):
        raise ValueError("Aggregate record count mismatch.")
    for field in DOMAIN["fields"]:
        names = [name for name, metric in METRICS.items() if metric.get("field") == field["name"] and metric["kind"] == "count"]
        if names and sum(raw_results[name] for name in names) != len(aggregate["records"]):
            raise ValueError("Category count mismatch.")
    save("tally", "final_totals.json", {"completed_at": now(), "results": results})
    show_summary("Threshold decrypt aggregate", results)
    return results


def entity_menu(entity):
    if ROLE != entity:
        raise PermissionError("Wrong entity session.")
    while True:
        print("\n------ " + entity + " ------")
        print("Workflow:", " -> ".join(ENTITIES[entity]) or "none")
        print("1. Run workflow\n2. Back")
        choice = input("Enter choice: ").strip()
        if choice == "2":
            return
        if choice != "1":
            print("Invalid choice.")
            continue
        selected = ENTITIES[entity]
        record_id = None
        if any(action in selected for action in ("submit_record", "verify_record", "view_record")):
            record_id = input(DOMAIN["record_name"] + " ID: ").strip()
            record_filename(record_id)
        for action in DOMAIN_ACTIONS:
            if action not in selected:
                continue
            if action == "submit_record":
                values = {}
                for field in DOMAIN["fields"]:
                    suffix = " (" + ", ".join(field["choices"]) + ")" if field["type"] == "choice" else ""
                    values[field["name"]] = input(field["name"] + suffix + ": ")
                submit_record(record_id, values)
            elif action == "verify_record":
                verify_record(record_id)
            elif action == "view_record":
                view_record(record_id)
            elif action == "search_records":
                search_records()
            elif action == "aggregate_records":
                aggregate_records()
            elif action == "threshold_decrypt":
                threshold_decrypt()


def main():
    global ROLE
    setup()
    names = list(ENTITIES)
    while True:
        print("\n" + DOMAIN["title"])
        for number, name in enumerate(names, 1):
            print(f"{number}. {name}")
        print(f"{len(names)+1}. Exit")
        choice = input("Enter choice: ").strip()
        if choice == str(len(names)+1):
            break
        if not choice.isdigit() or not 1 <= int(choice) <= len(names):
            print("Invalid choice.")
            continue
        entity = names[int(choice)-1]
        try:
            if login(entity):
                ROLE = entity
                entity_menu(entity)
        except (OSError, ValueError, KeyError, TypeError, IndexError, PermissionError, InvalidOperation) as error:
            print("Workflow stopped:", error)
        finally:
            ROLE = None


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nProgram closed.")
'''


def validate_domain(domain):
    if not isinstance(domain, dict):
        raise ValueError('Domain configuration must be a dictionary.')
    result = {'title': str(domain.get('title','')).strip(),
              'record_name': str(domain.get('record_name','')).strip()}
    if not result['title'] or not result['record_name']:
        raise ValueError('Enter a system title and record name.')
    fields = domain.get('fields')
    if not isinstance(fields,list) or not 1 <= len(fields) <= 50:
        raise ValueError('Configure 1 to 50 fields.')
    result['fields'] = []
    seen = set()
    for raw in fields:
        name = str(raw.get('name','')).strip()
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,39}',name) or name.casefold() in seen:
            raise ValueError('Use unique field names starting with a letter, with letters/digits/underscores only.')
        seen.add(name.casefold())
        kind = raw.get('type')
        if kind not in ('text','integer','decimal','choice'):
            raise ValueError('Field type must be text, integer, decimal or choice.')
        f = {'name':name,'type':kind,'search':raw.get('search',False),
             'sum':raw.get('sum',False),'count':raw.get('count',False)}
        if not all(isinstance(f[k],bool) for k in ('search','sum','count')):
            raise ValueError('Search, sum and count flags must be booleans.')
        if f['sum'] and kind not in ('integer','decimal'):
            raise ValueError('Only numeric fields can be summed.')
        if f['count'] and kind != 'choice':
            raise ValueError('Category counts require a choice field.')
        if kind == 'decimal':
            scale = raw.get('decimals',2)
            if type(scale) is not int or not 1 <= scale <= 6:
                raise ValueError('Choose 1 to 6 decimal places.')
            f['decimals'] = scale
        if kind == 'choice':
            choices = raw.get('choices')
            if not isinstance(choices,list) or not 1 <= len(choices) <= 30:
                raise ValueError('Configure 1 to 30 choices.')
            choices = [str(c).strip() for c in choices]
            if any(not c for c in choices) or len({c.casefold() for c in choices}) != len(choices):
                raise ValueError('Choices must be nonempty and unique, ignoring case.')
            f['choices'] = choices
        result['fields'].append(f)
    for key,default in (('use_deadline',False),('close_on_aggregate',False)):
        result[key] = domain.get(key,default)
        if not isinstance(result[key],bool):
            raise ValueError(key+' must be boolean.')
    result['min_records'] = domain.get('min_records',2)
    if type(result['min_records']) is not int or not 1 <= result['min_records'] <= 100000:
        raise ValueError('Minimum aggregate size must be 1..100000.')
    return result


def make_metrics(domain):
    metrics = {'record_count':{'kind':'record_count','label':'Record count','scale':1,'decimals':0}}
    for i, field in enumerate(domain['fields']):
        if field['sum']:
            decimals = field.get('decimals',0)
            metrics[f'sum_{i}']={'kind':'sum','label':'Total '+field['name'], 'field':field['name'],
                                'scale':10**decimals,'decimals':decimals}
        if field['count']:
            for j, choice in enumerate(field['choices']):
                metrics[f'count_{i}_{j}']={'kind':'count','label':field['name']+' = '+choice,
                    'field':field['name'],'choice':choice,'scale':1,'decimals':0}
    return metrics


def build_domain_source(domain, entities, algorithms=None):
    algorithms = validate_algorithms(algorithms)
    domain = validate_domain(domain)
    entities = validate_entities(entities, DOMAIN_ACTIONS)
    tree = ast.parse(TEMPLATE)
    first_function = next(n for n in tree.body if isinstance(n,ast.FunctionDef))
    header = ''.join(TEMPLATE.splitlines(keepends=True)[:first_function.lineno-1])
    header = header.replace('election_files','record_files').replace('CANDIDATES = [1, 2, 3]','')
    header += '\nALGORITHMS = '+repr(algorithms)+'\n'
    header += '\nDOMAIN = '+repr(domain)+'\nENTITIES = '+repr(entities)+'\n'
    header += 'DOMAIN_ACTIONS = '+repr(DOMAIN_ACTIONS)+'\nMETRICS = '+repr(make_metrics(domain))+'\n\n'
    keep = {'now','save','read','timed','show_summary','password_key','new_password','login',
            'protect_share','unlock_share','setup','aes_encrypt','aes_decrypt','rsa_encrypt_key','rsa_decrypt_key',
            'hash_message','generate_signing_keys','sign_hash','signature_values','verify_signature',
            'paillier_encrypt','search_token','seal'}
    parts = [header]
    for node in tree.body:
        if isinstance(node,ast.FunctionDef) and node.name in keep:
            text = ast.get_source_segment(TEMPLATE,node)
            if node.name == 'setup':
                text=text.replace('for role in ("voter", "server", "tally"):', 'for role in ENTITIES:')
                text=text.replace('election_files','record_files').replace('FIRST-RUN ELECTION SETUP','FIRST-RUN SYSTEM SETUP')
                text=text.replace('Voting starts:','Submissions start:').replace('Voting deadline:','Submission deadline:')
                rsa_start = text.index('    print("Generating RSA-4096 keys...")')
                rsa_end = text.index('    print("Generating Paillier parameters...")', rsa_start)
                rsa_setup = text[rsa_start:rsa_end]
                rsa_setup = rsa_setup.replace('print("Generating RSA-4096 keys...")', 'print("Generating RSA-" + str(ALGORITHMS["rsa_bits"]["key"]) + " keys...")')
                rsa_setup = rsa_setup.replace('RSA.generate(4096)', 'RSA.generate(ALGORITHMS["rsa_bits"]["key"])')
                text = text[:rsa_start] + '    if ALGORITHMS["key"] == "RSA":\n' + ''.join('    '+line if line.strip() else line for line in rsa_setup.splitlines(keepends=True)) + text[rsa_end:]

                if not domain['use_deadline']:
                    start=text.index('    start = datetime.strptime(')
                    end=text.index('    accounts = {}',start)
                    text=text[:start]+'    start = datetime(1970, 1, 1)\n    deadline = datetime(9999, 12, 31, 23, 59, 59)\n\n'+text[end:]
                text=text.replace('    if any((BASE / folder).iterdir() for folder in []):\n        pass\n\n','')
            parts.append(text+'\n\n')
    parts.append(ALGORITHM_RUNTIME)
    runtime = DOMAIN_RUNTIME.replace('key = os.urandom(32)', 'key = document_key()')
    runtime = runtime.replace('"AES encryption"', 'ALGORITHMS["encryption"] + " encryption"').replace('"AES decryption"', 'ALGORITHMS["encryption"] + " decryption"')
    runtime = runtime.replace('"RSA key encryption"', 'ALGORITHMS["key"] + " key encryption"').replace('"RSA key decryption"', 'ALGORITHMS["key"] + " key decryption"')
    for old, new in [('"SHA-512"', 'ALGORITHMS["hash"]'), ('"Stored SHA-512"', '"Stored " + ALGORITHMS["hash"]'), ('"Computed SHA-512"', '"Computed " + ALGORITHMS["hash"]'), ('"ElGamal signature"', 'ALGORITHMS["signature"] + " signature"'), ('"AES ciphertext"', 'ALGORITHMS["encryption"] + " ciphertext"'), ('"RSA-wrapped key"', 'ALGORITHMS["key"] + "-wrapped key"')]:
        runtime = runtime.replace(old, new)
    runtime = runtime.replace('search_token(field["name"]', 'index_token(field["name"]').replace('search_token("minute:" + timestamp[:16])', 'index_token("minute:" + timestamp[:16])')
    runtime = runtime.replace('read("index", filename) != make_index(record, timestamp)', 'not indexes_match(read("index", filename), make_index(record, timestamp))')
    runtime = runtime.replace('read("index", file.name).get(index_field) not in tokens', 'stored_search_token(read("index", file.name).get(index_field)) not in tokens')
    parts.append(runtime)
    source=''.join(parts)
    ast.parse(source)
    return source,domain,entities


def create_domain_solution(domain, entities, output_dir, algorithms=None):
    algorithms = validate_algorithms(algorithms)
    source,domain,entities = build_domain_source(domain,entities,algorithms)
    directory = Path(output_dir).resolve()
    directory.mkdir(parents=True,exist_ok=False)
    artifacts={
        'solution.py':source,
        'algorithms.json':json.dumps(algorithms,indent=2),
        'domain.json':json.dumps(domain,indent=2,ensure_ascii=False),
        'entities.json':json.dumps(entities,indent=2,ensure_ascii=False),
        'requirements.txt':'pycryptodome\n',
        '.gitignore':'record_files/\n__pycache__/\n*.py[cod]\n',
        'RUN.txt':f'''{domain['title']}

Install: python -m pip install -r requirements.txt
Run: python solution.py

First run sets entity passwords and BOTH authority passwords. Password input is
hidden. Submission dates are requested only if you enabled a deadline.
Select an entity, log in, and run its entire assigned workflow. The record ID
is requested once. Verification does not display plaintext; view_record does.
Signature/hash comparisons and timings are printed once per verification action.

FIELDS AND TOTALS
Fields and entity permissions are documented in domain.json and entities.json;
the standalone program embeds the configuration. Generate a NEW solution folder
to change schema or roles. Existing record folders are never overwritten.
Text fields accept arbitrary nonempty text; search is exact-value, case-insensitive.
Integer/decimal fields accept nonnegative values up to 10^18 scaled units.
Decimals use fixed-point integers, never floating-point arithmetic, for totals.
Numeric sums and category counts are selected during generation. Record count
is always included. Each choice field has encrypted 0/1 counts per choice.
Time search uses the original minute-token index and exact timestamp filtering;
queries can span at most seven days. Search reveals IDs, not record contents.

CRYPTO AND STORAGE
Selected algorithms: {json.dumps(algorithms)}. See algorithms.json.
RSA sizes are configured separately for key protection, signatures and PKSE search.
Only selected RSA uses generate keys; restarting reuses stored wrapping/search keys.
Paillier totals, passwords, receipts and two-authority aggregate decryption
retain the original design. No sockets. RSA signatures use PKCS#1 v1.5 with
SHA-256 over the selected document digest; Schnorr uses a SHA-256 challenge.
SSE uses HMAC-SHA256 tokens. PKSE lab mode encrypts keyword hashes with RSA-OAEP
and scans using the private search key; it is not trapdoor-based PEKS.
DES, Triple-DES, MD5 and SHA-1 are provided for legacy lab exercises.
Records are stored under record_files/ in the original separate-file layout.
Every submitted record must be verified before aggregating. Minimum aggregate
size: {domain['min_records']}. Close submissions on aggregation: {domain['close_on_aggregate']}.
If submissions stay open, adding records makes the previous aggregate stale;
verify the new records and aggregate again before threshold decryption.
Only the combined ciphertext is decrypted by the threshold menu. Both authority
passwords are required. Local role and timestamp trust remain a lab simulation.
Choosing a minimum aggregate size of one does not conceal that single record's
numeric values. Public category definitions and repeated aggregate releases can
also reveal information; this is not a production privacy system.

SCOPE
Supports configurable record-based lab scenarios (hospital, university, bank,
warehouse, election, etc.) with encrypted sums and category counts. It does not
automatically invent field-specific rules such as loan approval, diagnosis,
eligibility, negative-value accounting, or custom cryptographic algorithms.
'''}
    for name,content in artifacts.items():
        (directory/name).write_text(content,encoding='utf-8')
    return directory/'solution.py'


def ask_yes(prompt, default=False):
    while True:
        answer=input(prompt+(' [Y/n]: ' if default else ' [y/N]: ')).strip().lower()
        if not answer:
            return default
        if answer in ('y','yes'):
            return True
        if answer in ('n','no'):
            return False
        print('Enter yes or no.')


def ask_number(prompt,low,high,default=None):
    while True:
        answer=input(prompt+(f' [{default}]' if default is not None else '')+': ').strip()
        if not answer and default is not None:
            return default
        if answer.isdigit() and low <= int(answer) <= high:
            return int(answer)
        print(f'Enter an integer from {low} to {high}.')


def choose_domain():
    while True:
        title=input('System/domain title (e.g. Hospital Records): ').strip()
        record_name=input('Record name (e.g. report, invoice, application): ').strip()
        if title and record_name:
            break
        print('Both names are required.')
    count=ask_number('Number of record fields',1,50)
    fields=[]
    for i in range(count):
        while True:
            name=input(f'Field {i+1} name (e.g. patient_name, department, bill_amount): ').strip()
            if re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,39}',name) and name.casefold() not in {f['name'].casefold() for f in fields}:
                break
            print('Use a unique field name: letters/digits/underscores, starting with a letter.')
        while True:
            kind=input('Type: text / integer / decimal / choice: ').strip().lower()
            if kind in ('text','integer','decimal','choice'):
                break
            print('Choose a listed type.')
        field={'name':name,'type':kind}
        if kind=='decimal':
            field['decimals']=ask_number('Decimal places',1,6,2)
        if kind=='choice':
            while True:
                options=[x.strip() for x in input('Allowed choices, comma separated: ').split(',')]
                if 1 <= len(options) <= 30 and all(options) and len({x.casefold() for x in options})==len(options):
                    field['choices']=options
                    break
                print('Enter 1..30 unique nonempty choices.')
        field['search']=ask_yes('Allow exact-value search on this field?')
        field['sum']=ask_yes('Compute an encrypted sum for this field?') if kind in ('integer','decimal') else False
        field['count']=ask_yes('Compute encrypted counts for each choice?') if kind=='choice' else False
        fields.append(field)
    domain={'title':title,'record_name':record_name,'fields':fields,
            'use_deadline':ask_yes('Enforce a submission period/deadline?'),
            'close_on_aggregate':ask_yes('Close submissions after aggregation?'),
            'min_records':ask_number('Minimum verified records before aggregate decryption',1,100000,2)}
    return validate_domain(domain)


def main():
    print('GENERAL RECORD-BASED CRYPTO LAB GENERATOR')
    print('Configure your fields, searchable values, encrypted totals/counts and entity workflows.')
    print('Original crypto suite: AES-256, RSA-4096, SHA-512, ElGamal, Paillier and SSE.')
    domain=choose_domain()
    algorithms=choose_algorithms()
    entities=choose_entities(DOMAIN_ACTIONS)
    print('\nSystem:',domain['title'])
    print('Record:',domain['record_name'])
    for name,metric in make_metrics(domain).items():
        print('Encrypted aggregate:',metric['label'])
    for name,permissions in entities.items():
        print(name+': '+(', '.join(permissions) or 'none'))
    slug=re.sub(r'[^A-Za-z0-9_-]+','_',domain['title']).strip('_')[:80] or 'records'
    default=Path(__file__).resolve().parent/'GENERATED_DOMAINS'/('CUSTOM_'+slug)
    while True:
        answer=input(f'NEW output folder (Enter for {default}): ').strip()
        try:
            file=create_domain_solution(domain,entities,Path(answer).expanduser() if answer else default, algorithms=algorithms)
            break
        except FileExistsError:
            print('Folder exists. Choose a new folder to preserve its records and keys.')
        except (ValueError,OSError) as error:
            print('Could not create solution:',error)
    print('Created:',file)
    print('Open its folder and run python solution.py')



ALGORITHM_CHOICES = {
    'encryption': ['AES-256', 'AES-128', 'AES-192', 'DES', 'Triple-DES'],
    'hash': ['SHA-512', 'SHA-256', 'SHA-1', 'MD5'],
    'key': ['RSA', 'ECDH'],
    'signature': ['ElGamal', 'RSA', 'Schnorr'],
    'search': ['SSE', 'PKSE'],
}


RSA_KEY_SIZES = (2048, 3072, 4096)
RSA_DEFAULT_BITS = {'key':4096, 'signature':2048, 'search':2048}


def validate_algorithms(algorithms=None):
    supplied = {} if algorithms is None else algorithms
    if not isinstance(supplied, dict) or set(supplied) - (set(ALGORITHM_CHOICES) | {'rsa_bits'}):
        raise ValueError('Unknown algorithm category.')
    result = {}
    for category, choices in ALGORITHM_CHOICES.items():
        value = supplied.get(category, choices[0])
        normalized = str(value).lower().replace('-', '').replace('_', '').replace(' ', '')
        matches = [choice for choice in choices if choice.lower().replace('-', '') == normalized]
        if not matches:
            raise ValueError('Unsupported ' + category + ': ' + str(value))
        result[category] = matches[0]
    sizes = supplied.get('rsa_bits', {})
    if not isinstance(sizes, dict) or set(sizes) - set(RSA_DEFAULT_BITS):
        raise ValueError('RSA sizes must specify key, signature, or search.')
    result['rsa_bits'] = dict(RSA_DEFAULT_BITS)
    for purpose, bits in sizes.items():
        if type(bits) is not int or bits not in RSA_KEY_SIZES:
            raise ValueError('RSA key size must be 2048, 3072, or 4096 bits.')
        result['rsa_bits'][purpose] = bits
    return result


def choose_algorithms():
    print('\nCHOOSE CRYPTO ALGORITHMS (Enter keeps the original default)')
    selected = {'rsa_bits': dict(RSA_DEFAULT_BITS)}
    for category, choices in ALGORITHM_CHOICES.items():
        print(category.title() + ': ' + ', '.join(f'{i}. {name}' for i, name in enumerate(choices, 1)))
        while True:
            answer = input(f'{category.title()} algorithm [{choices[0]}]: ').strip()
            if answer.isdigit() and 1 <= int(answer) <= len(choices):
                answer = choices[int(answer)-1]
            try:
                selected[category] = validate_algorithms({category: answer or choices[0]})[category]
                break
            except ValueError as error:
                print(error)
        if (category in ('key', 'signature') and selected[category] == 'RSA') or (category == 'search' and selected[category] == 'PKSE'):
            label = {'key':'key protection', 'signature':'digital signatures', 'search':'PKSE search'}[category]
            while True:
                answer = input(f'RSA bits for {label}: 2048 / 3072 / 4096 [{RSA_DEFAULT_BITS[category]}]: ').strip()
                if not answer:
                    break
                if answer.isdigit() and int(answer) in RSA_KEY_SIZES:
                    selected['rsa_bits'][category] = int(answer)
                    break
                print('Enter 2048, 3072, or 4096, or press Enter for the default.')
    print('Homomorphic totals: Paillier (required for sums and two-authority decryption).')
    if selected['search'] == 'PKSE':
        print('PKSE lab mode: RSA-encrypted keyword hashes; private-key scan, not trapdoor PEKS.')
    return selected


ALGORITHM_RUNTIME = r"""
from Crypto.Cipher import DES, DES3
from Crypto.PublicKey import ECC, DSA
from Crypto.Protocol.DH import key_agreement
from Crypto.Signature import pkcs1_15

_original_setup = setup
_original_generate_signing_keys = generate_signing_keys
_original_sign_hash = sign_hash
_original_signature_values = signature_values
_original_encrypt_key = rsa_encrypt_key
_original_decrypt_key = rsa_decrypt_key
_original_search_token = search_token


def setup():
    _original_setup()
    if ALGORITHMS['key'] == 'ECDH' and not (BASE/'keys'/'ecdh_private.json').exists():
        key = ECC.generate(curve='P-256')
        save('keys', 'ecdh_private.json', key.export_key(format='PEM'))
        save('keys', 'ecdh_public.json', key.public_key().export_key(format='PEM'))
    if ALGORITHMS['signature'] == 'Schnorr' and not (BASE/'keys'/'schnorr.json').exists():
        group = DSA.generate(2048)
        save('keys', 'schnorr.json', {name: int(getattr(group, name)) for name in ('p','q','g')})
    if ALGORITHMS['search'] == 'PKSE' and not (BASE/'keys'/'search_private.json').exists():
        key = RSA.generate(ALGORITHMS['rsa_bits']['search'])
        save('keys', 'search_private.json', key.export_key().decode())
        save('keys', 'search_public.json', key.publickey().export_key().decode())


def document_key():
    size = {'AES-128':16, 'AES-192':24, 'AES-256':32, 'DES':8, 'Triple-DES':24}[ALGORITHMS['encryption']]
    key = os.urandom(size)
    return DES3.adjust_key_parity(key) if ALGORITHMS['encryption'] == 'Triple-DES' else key


def document_cipher():
    return {'DES':DES, 'Triple-DES':DES3}.get(ALGORITHMS['encryption'], AES)


def aes_encrypt(plaintext, key):
    algorithm = document_cipher()
    cipher = algorithm.new(key, algorithm.MODE_CBC)
    return cipher.iv.hex(), cipher.encrypt(pad(plaintext.encode(), algorithm.block_size)).hex()


def aes_decrypt(ciphertext, key, iv):
    algorithm = document_cipher()
    cipher = algorithm.new(key, algorithm.MODE_CBC, iv=bytes.fromhex(iv))
    return unpad(cipher.decrypt(bytes.fromhex(ciphertext)), algorithm.block_size).decode()


def hash_message(message):
    return hashlib.new(ALGORITHMS['hash'].lower().replace('-', ''), message.encode()).hexdigest()


def rsa_encrypt_key(key):
    if ALGORITHMS['key'] == 'RSA':
        return _original_encrypt_key(key)
    ephemeral = ECC.generate(curve='P-256')
    public = ECC.import_key(read('keys', 'ecdh_public.json'))
    secret = key_agreement(eph_priv=ephemeral, static_pub=public, kdf=lambda x: SHA256.new(x).digest())
    cipher = AES.new(secret, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(key)
    return {'public':ephemeral.public_key().export_key(format='PEM'), 'nonce':cipher.nonce.hex(),
            'tag':tag.hex(), 'ciphertext':ciphertext.hex()}


def rsa_decrypt_key(ciphertext):
    if ALGORITHMS['key'] == 'RSA':
        return _original_decrypt_key(ciphertext)
    private = ECC.import_key(read('keys','ecdh_private.json'))
    public = ECC.import_key(ciphertext['public'])
    secret = key_agreement(static_priv=private, eph_pub=public, kdf=lambda x: SHA256.new(x).digest())
    cipher = AES.new(secret, AES.MODE_EAX, nonce=bytes.fromhex(ciphertext['nonce']))
    return cipher.decrypt_and_verify(bytes.fromhex(ciphertext['ciphertext']), bytes.fromhex(ciphertext['tag']))


def generate_signing_keys():
    if ALGORITHMS['signature'] == 'ElGamal':
        return _original_generate_signing_keys()
    if ALGORITHMS['signature'] == 'RSA':
        key = RSA.generate(ALGORITHMS['rsa_bits']['signature'])
        return key.export_key(), {'pem':key.publickey().export_key().decode()}
    group = read('keys','schnorr.json')
    private = secrets.randbelow(group['q']-1)+1
    return private, {**group, 'y':pow(group['g'],private,group['p'])}


def schnorr_challenge(digest, commitment, public):
    message = json.dumps([digest, commitment, public['p'], public['q'], public['g'], public['y']], separators=(',', ':'))
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big') % public['q']


def sign_hash(digest, private, public):
    if ALGORITHMS['signature'] == 'ElGamal':
        return _original_sign_hash(digest, private, public)
    if ALGORITHMS['signature'] == 'RSA':
        return pkcs1_15.new(RSA.import_key(private)).sign(SHA256.new(bytes.fromhex(digest))).hex()
    nonce = secrets.randbelow(public['q']-1)+1
    commitment = pow(public['g'],nonce,public['p'])
    challenge = schnorr_challenge(digest,commitment,public)
    return [challenge, (nonce+private*challenge) % public['q']]


def signature_values(digest, signature, public):
    if ALGORITHMS['signature'] == 'ElGamal':
        return _original_signature_values(digest, signature, public)
    if ALGORITHMS['signature'] == 'RSA':
        key = RSA.import_key(public['pem'])
        # PKCS#1 v1.5 SHA-256 DigestInfo, signing the selected document digest.
        info = bytes.fromhex('3031300d060960864801650304020105000420') + SHA256.new(bytes.fromhex(digest)).digest()
        size = key.size_in_bytes()
        expected = b'\x00\x01' + b'\xff'*(size-len(info)-3) + b'\x00' + info
        data = bytes.fromhex(signature)
        value = int.from_bytes(data,'big')
        if len(data) != size or value >= key.n:
            return expected.hex(), 'INVALID SIGNATURE'
        return expected.hex(), pow(value,key.e,key.n).to_bytes(size,'big').hex()
    challenge, response = signature
    if not (0 <= challenge < public['q'] and 0 <= response < public['q']):
        return 'VALID RANGE', 'INVALID SIGNATURE'
    commitment = pow(public['g'],response,public['p']) * pow(pow(public['y'],challenge,public['p']),-1,public['p']) % public['p']
    return challenge, schnorr_challenge(digest,commitment,public)


def search_token(value):
    if ALGORITHMS['search'] == 'SSE':
        return _original_search_token(value)
    return hashlib.sha256(value.encode()).hexdigest()


def index_token(value):
    token = search_token(value)
    if ALGORITHMS['search'] == 'SSE':
        return token
    public = RSA.import_key(read('keys','search_public.json'))
    return PKCS1_OAEP.new(public,hashAlgo=SHA256).encrypt(bytes.fromhex(token)).hex()


def stored_search_token(token):
    if ALGORITHMS['search'] == 'SSE':
        return token
    private = RSA.import_key(read('keys','search_private.json'))
    return PKCS1_OAEP.new(private,hashAlgo=SHA256).decrypt(bytes.fromhex(token)).hex()


def indexes_match(stored, expected):
    return set(stored) == set(expected) and all(hmac.compare_digest(stored_search_token(stored[k]), stored_search_token(expected[k])) for k in stored)
"""

if __name__=='__main__':
    try:
        main()
    except (KeyboardInterrupt,EOFError):
        print('\nGenerator closed.')
