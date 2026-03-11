'''
Programming assignment 1
'''



def register():
    '''
    '''
    pass


def store():
    '''
    '''
    pass


def read():
    '''
    '''
    pass


def tamper():
    '''
    '''
    pass


def delete_user():
    '''
    '''
    pass


def main():
    '''
    main function
    '''
    print('1.Register\n2.Store\n3.Read\n4.Tamper\n5.DeleteUser\n6.Exit')
    inpt = input()

    try:
        selected_option = int(inpt.strip())
    except Exception as e:
        raise Exception('Error, not a number, try again, ernter a number...')
    
    if selected_option < 1 or selected_option > 6:
        print('Error, enter correct option...\n')
        main()
    else:
        if selected_option == 1:
            register()
        elif selected_option == 2:
            store()
        elif selected_option == 3:
            read()
        elif selected_option == 4:
            tamper()
        elif selected_option == 5:
            delete_user()
        elif selected_option == 6:
            exit()




try:
    if __name__ == '__main__':
        main()
except Exception as e:
    print(f'Error - {e}')