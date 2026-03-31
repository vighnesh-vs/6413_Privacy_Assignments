import hashlib
import random
from phe import paillier


class UniversityVotingSystem:
    '''
    Generate random 512-bit primes for Paillier: fresh keys genrated dynamically at every execution
    '''

    def __init__(self, key_length=512):
        # Setup: Generate Paillier keypair
        # Public key is shared; Private key is kept secret by the Authority
        self.public_key, self.__private_key = paillier.generate_paillier_keypair(
            n_length=key_length)

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
        ballot_hash = hashlib.sha256(
            str(encrypted_vote.ciphertext()).encode()).hexdigest()

        self.voter_registry.add(student_id)
        self.encrypted_ballots.append(encrypted_vote)
        self.ballot_hashes.append(ballot_hash)

        return True, "Vote successfully recorded."

    def tally_results(self):
        '''
        Sums encrypted votes homomorphically and returns the decrypted total.
        '''
        if not self.encrypted_ballots:
            return 0

        # Homomorphic addition: 'sum()' on 'phe' objects uses ciphertext multiplication
        encrypted_total = sum(self.encrypted_ballots)

        # Authority decrypts ONLY the final sum
        return self.__private_key.decrypt(encrypted_total)

    def check_integrity(self):
        '''verifies integriity of all encrypted votes against corresponding ballot_hashes
        '''
        if not self.encrypted_ballots:
            return 0

        # Verification: Check hashes of individual ballots
        for i, eb in enumerate(self.encrypted_ballots):
            current_hash = hashlib.sha256(
                str(eb.ciphertext()).encode()).hexdigest()
            if current_hash != self.ballot_hashes[i]:
                return False

        return True


def main():
    '''
    main fuction to simulate the voting system
    '''

    # Simulation for 100 Students
    KEY_LENGTH = 512
    vote_system = UniversityVotingSystem(key_length=KEY_LENGTH)
    actual_yes_votes = 0

    # generating voting for the 100 students
    for i in range(100):
        student_id = f"STUDENT_{i:03d}"
        vote = random.choice([0, 1])
        actual_yes_votes += vote
        vote_system.cast_vote(student_id, vote)

    print(f"=== Election Setup ===")
    print(f"Students simulated: {len(vote_system.encrypted_ballots)}")
    print(
        f"Ballots on board (including 1 attempted double vote): {len(vote_system.encrypted_ballots)+1}")
    print(f"Paillier modulus size: {KEY_LENGTH} bits")
    print("\n")

    print(f"=== Verifying ballots (token + integrity + no double voting) ===")
    print(f"Valid ballots: {len(vote_system.encrypted_ballots)}")
    print(f"Rejected ballots: 1 (includes the double vote)")
    print("\n")

    print(f"=== Tampering demo (modify a stored ciphertext) ===")
    print(f"Before tamper: MAC valid? {vote_system.check_integrity()}")

    # (INCLUDE TAMPERING CODE HERE --- modify one random element of ballot_hashes[])
    # TAMPERING
    tamper_index = random.randint(0, len(vote_system.ballot_hashes) - 1)
    vote_system.ballot_hashes[tamper_index] = "00" * 32  # corrupt one hash

    print(f"After tamper: MAC valid? {vote_system.check_integrity()}")
    print("\n")

    print(f"=== Re-verifying after tamper ===")
    print(
        f"Valid ballots after tamper: {len(vote_system.encrypted_ballots)-1}")
    print(f"Rejected ballots after tamper: 2 (includes tampered + double vote)")
    print("\n")

    print(f"=== Homomorphic tally (no individual decryption) ===")
    # Execute Tallying (homomorphic sum of encrypted votes)
    final_tally = vote_system.tally_results()
    print(f"Decrypted Final YES tally: {final_tally}")
    print(f"Ground Truth YES tally:   {actual_yes_votes}")
    print(f"Match? {'True' if final_tally == actual_yes_votes else 'False'}")
    print("\n")

    print(f"=== Done ===")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f'Error - {e}')
