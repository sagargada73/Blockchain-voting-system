from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
import json
import time
import os

from flask_cors import CORS

import logging

logging.basicConfig(level=logging.DEBUG)

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return SHA256.new(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.registered_voters = {}  # Store registered voters' public keys
        self.vote_counts = {}

    def create_commitment(self):
        # Create a commitment by hashing the vote and nonce
        commitment_string = f"{self.vote}{self.nonce}"
        return SHA256.new(commitment_string.encode()).hexdigest()

    def verify_commitment(self, revealed_vote):
        # Verify if the revealed vote matches the original commitment
        commitment_string = f"{revealed_vote}{self.nonce}"
        return self.commitment == SHA256.new(commitment_string.encode()).hexdigest()
    
    def create_genesis_block(self):
        return Block(0, [], int(time.time()), "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, block):
        block.previous_hash = self.get_latest_block().hash
        block.hash = block.calculate_hash()
        self.chain.append(block)

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)
        candidate = transaction['vote']
        if candidate not in self.vote_counts:
            self.vote_counts[candidate] = 0
        self.vote_counts[candidate] += 1

    def mine_pending_transactions(self):
        block = Block(len(self.chain), self.pending_transactions, int(time.time()), self.get_latest_block().hash)
        self.add_block(block)
        self.pending_transactions = []

    def register_voter(self, voter_id, public_key):
        self.registered_voters[voter_id] = public_key

    def is_registered_voter(self, voter_id):
        return voter_id in self.registered_voters

    def get_voter_public_key(self, voter_id):
        return self.registered_voters.get(voter_id)
    
    def has_voted(self, voter_id):
        for block in self.chain:
            for transaction in block.transactions:
                if transaction['voter_id'] == voter_id:
                    return True
        for transaction in self.pending_transactions:
            if transaction['voter_id'] == voter_id:
                return True
        return False


class Transaction:
    def __init__(self, voter_id, vote):
        self.voter_id = voter_id
        self.vote = vote
        self.nonce = os.urandom(16).hex()  # Generate a 16-byte random nonce
        self.commitment = self.create_commitment()

    def create_commitment(self):
        commitment_string = f"{self.vote}{self.nonce}"
        return SHA256.new(commitment_string.encode()).hexdigest()

    def verify_commitment(self, revealed_vote):
        commitment_string = f"{revealed_vote}{self.nonce}"
        return self.commitment == SHA256.new(commitment_string.encode()).hexdigest()

    def sign_transaction(self, private_key):
        transaction_string = json.dumps(self.__dict__, sort_keys=True)
        hash_object = SHA256.new(transaction_string.encode())
        signature = pkcs1_15.new(private_key).sign(hash_object)
        return signature

blockchain = Blockchain()
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app,cors_allowed_origins="*")

# Store public keys (replace with database in the future)
public_keys = {}
public_keys['3'] = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApWLALVCsEFvhsrA/gjdo\nJKi5TAfIYLWxPzM2CvxX82ikMD+F+H2czWRDfL6njdW2AX+hcko/KJ990aygC3kl\ndFZaloTCi00/AAhirosZi6cArUeCVWI4XQKquAXqCJhYPsjrromV406EbVMyYoYV\nEfUayMJO6Fkl0/lFsy4NFoK7Ooup9pWPgktTswi3n1G1ciLy8CQrLqWuNc9rPsww\nxFMR3HdCAJq0xlNHbcYEziHVKQbg5cgEWKbwDSYMYesRhS//3j//f9Cp1Bkf6kgW\nvnypKIq6Atv3FQAhR3YdLHMkFAU6x9Ia2d6g6TryV25ws5naUf3hZj1K3FCe5XCB\nOwIDAQAB\n-----END PUBLIC KEY-----"
@app.route('/register', methods=['POST'])
def register_voter():
    voter_id = request.json['voter_id']
    
    # Generate key pair
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    
    # Store public key
    public_keys[voter_id] = public_key
    
    logging.debug(f"Registered voter {voter_id}. Public keys: {public_keys}")
    
    # Return both keys to the user
    return jsonify({
        "message": "Voter registered successfully",
        "public_key": public_key,
        "private_key": private_key
    }), 201

@app.route('/vote', methods=['POST'])
def vote():
    logging.info("Vote endpoint called")
    logging.debug(f"Current public keys: {public_keys}")

    try:
        voter_id = request.json['voter_id']
        vote = request.json['vote']
        signature = request.json['signature']
        logging.info(f"Received vote request for voter {voter_id}")
    except KeyError as e:
        logging.error(f"Missing required field: {str(e)}")
        return jsonify({"message": f"Missing required field: {str(e)}"}), 400

    if voter_id not in public_keys:
        logging.error(f"Voter {voter_id} not registered")
        return jsonify({"message": f"Voter {voter_id} not registered"}), 400

    try:
        signature_bytes = bytes.fromhex(signature)
        logging.debug("Signature converted to bytes successfully")
    except ValueError:
        logging.error("Invalid signature format")
        return jsonify({"message": "Invalid signature format"}), 400

    public_key = RSA.import_key(public_keys[voter_id])
    logging.debug(f"Public key for voter {voter_id} retrieved")

    vote_data = {
        "voter_id": voter_id,
        "vote": vote
    }
    message = json.dumps(vote_data, sort_keys=True).encode()
    hash_object = SHA256.new(message)
    logging.debug(f"Vote data hash created: {hash_object.hexdigest()}")

    try:
        pkcs1_15.new(public_key).verify(hash_object, signature_bytes)
        logging.info("Signature verified successfully")
        
        # Create and add transaction
        transaction = Transaction(voter_id, vote)
        blockchain.add_transaction(transaction.__dict__)
        logging.info("Transaction added to blockchain")
        socketio.emit('vote_tally_update', blockchain.vote_counts)
        return jsonify({
            "message": "Vote added successfully",
            "commitment": transaction.commitment,
            "nonce": transaction.nonce
        }), 201
    except (ValueError, TypeError) as e:
        logging.error(f"Signature verification failed: {str(e)}")
        return jsonify({"message": f"Invalid signature: {str(e)}"}), 400
@app.route('/reveal_vote', methods=['POST'])
def reveal_vote():
    logging.info("Reveal vote endpoint called")
    logging.debug(f"Current public keys: {public_keys}")

    try:
        voter_id = request.json['voter_id']
        revealed_vote = request.json['vote']
        nonce = request.json['nonce']
    except KeyError as e:
        logging.error(f"Missing required field: {str(e)}")
        return jsonify({"message": f"Missing required field: {str(e)}"}), 400

    logging.info(f"Attempting to reveal vote for voter {voter_id}")

    # Find the transaction in pending transactions or blocks
    for block in blockchain.chain:
        for transaction in block.transactions:
            if transaction['voter_id'] == voter_id:
                logging.debug(f"Found transaction for voter {voter_id}")
                # Recreate the commitment
                commitment_string = f"{revealed_vote}{nonce}"
                new_commitment = SHA256.new(commitment_string.encode()).hexdigest()
                
                if new_commitment == transaction['commitment']:
                    logging.info(f"Vote verified successfully for voter {voter_id}")
                    return jsonify({"message": "Vote verified successfully"}), 200
                else:
                    logging.warning(f"Vote verification failed for voter {voter_id}")
                    return jsonify({"message": "Vote verification failed"}), 400
    
    logging.error(f"No transaction found for voter {voter_id}")
    return jsonify({"message": "No vote found for this voter"}), 404

@app.route('/sign_vote', methods=['POST'])
def sign_vote():
    voter_id = request.json['voter_id']
    vote = request.json['vote']
    private_key_str = request.json['private_key']

    try:
        private_key = RSA.import_key(private_key_str)
        vote_data = {
            "voter_id": voter_id,
            "vote": vote
        }
        message = json.dumps(vote_data, sort_keys=True).encode()
        hash_object = SHA256.new(message)
        signature = pkcs1_15.new(private_key).sign(hash_object)
        logging.info(f"Vote signed successfully for voter {voter_id}")
        logging.debug(f"Vote data: {vote_data}")
        logging.debug(f"Signature: {signature.hex()}")
        return jsonify({"signature": signature.hex()}), 200
    except Exception as e:
        logging.error(f"Error in sign_vote: {str(e)}")
        return jsonify({"error": str(e)}), 400
    
@app.route('/mine', methods=['GET'])
def mine():
    blockchain.mine_pending_transactions()
    return jsonify({"message": "Block mined successfully"}), 200

@app.route('/chain', methods=['GET'])
def get_chain():
    chain = []
    for block in blockchain.chain:
        chain.append(block.__dict__)
    return jsonify(chain), 200

@app.route('/vote_tally', methods=['GET'])
def vote_tally():
    return jsonify(blockchain.vote_counts), 200

if __name__ == '__main__':
    socketio.run(app, debug=True)

