import hashlib
import random
from phe import paillier

class PaillierPublicKey:
    pass


class PaillierPrivateKey:
    pass


def generate_paillier_keypair(bits=512):
    '''
    function to generate paillier key pair
    '''
    pass

def make_mac(student_id, ciphertext):
    pass


def check_mac(student_id, ciphertext, tag):
    '''
    should return boolean
    '''

class UniversityVotingSystem:
    
    # Generate random 512-bit primes for Paillier: fresh keys genrated dynamically at every execution

    def __init__(self, key_length=512):
        # Setup: Generate Paillier keypair
        # Public key is shared; Private key is kept secret by the Authority
        self.public_key, self.__private_key = paillier.generate_paillier_keypair(n_length=key_length)
        
        self.voter_registry = set()      # Prevents double voting
        self.encrypted_ballots = []     # Stores ciphertexts
        self.ballot_hashes = []         # For integrity checks

    def cast_vote(self, student_id, vote):
        """Encrypts and stores a student's vote with integrity protection."""
        if student_id in self.voter_registry:
            return False, "Error: Student has already voted."
        
        # 1 = YES, 0 = NO
        encrypted_vote = self.public_key.encrypt(vote)
        
        # Integrity: Hash the ciphertext to detect tampering
        ballot_hash = hashlib.sha256(str(encrypted_vote.ciphertext()).encode()).hexdigest()
        
        self.voter_registry.add(student_id)
        self.encrypted_ballots.append(encrypted_vote)
        self.ballot_hashes.append(ballot_hash)
        
        return True, "Vote successfully recorded."

    def tally_results(self):
        """Sums encrypted votes homomorphically and returns the decrypted total."""
        if not self.encrypted_ballots:
            return 0

        # Verification: Check hashes before tallying
        for i, eb in enumerate(self.encrypted_ballots):
            current_hash = hashlib.sha256(str(eb.ciphertext()).encode()).hexdigest()
            if current_hash != self.ballot_hashes[i]:
                raise ValueError(f"Integrity Breach detected at index {i}!")

        # Homomorphic addition: 'sum()' on 'phe' objects uses ciphertext multiplication
        encrypted_total = sum(self.encrypted_ballots)
        
        # Authority decrypts ONLY the final sum
        return self.__private_key.decrypt(encrypted_total)


def main():
    '''
    main fuction to simulate the voting system
    '''
    
    # --- Simulation for 100 Students ---
    
    vote_system = UniversityVotingSystem()
    actual_yes_votes = 0

    for i in range(100):
        student_id = f"STUDENT_{i:03d}"
        vote = random.choice([0, 1])
        actual_yes_votes += vote
        vote_system.cast_vote(student_id, vote)

    # Execute Tallying
    final_tally = vote_system.tally_results()
    
    print(f"--- Election Results ---")
    print(f"Total Ballots Cast: {len(vote_system.encrypted_ballots)}")
    print(f"Homomorphic Tally (Decrypted): {final_tally}")
    print(f"Verification (Actual count):   {actual_yes_votes}")
    print(f"Integrity Status: {'PASSED' if final_tally == actual_yes_votes else 'FAILED'}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f'Error - {e}')
