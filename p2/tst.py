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


def main():
    '''
    main fuction to simulate the voting system
    '''


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f'Error - {e}')