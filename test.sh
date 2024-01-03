#!/bin/bash
echo "Test: register with name: firstuser, key: picoctf{FIRSTSECRETKEY}"
./stor -u firstuser -k picoctf{FIRSTSECRETKEY} register user1inputtedtext123456789

echo "Test: register with name: seconduser, key: picoctf{SECONDSECRETKEY}"
./stor -u seconduser -k picoctf{SECONDSECRETKEY} register 'user2 inputted text'

echo "Test: register with name: thirduser, key: picoctf{THIRDSECRETKEY}"
./stor -u thirduser -k picoctf{THIRDSECRETKEY} register 'user3 inputted text'

# echo "Test: read with name: seconduser, key: picoctf{SECONDSECRETKEY}"
# ./stor -u seconduser -k picoctf{SECONDSECRETKEY} read

# echo "Test: read with name: baduser, key: picoctf{THIRDSECRETKEY}"
# ./stor -u baduser -k picoctf{THIRDSECRETKEY} read

# echo "Test: read with name: seconduser, key: picoctf{BADSECRETKEY}"
# ./stor -u seconduser -k picoctf{BADSECRETKEY} read

# echo "Test: read with name: thirduser, key: picoctf{THIRDSECRETKEY}"
# ./stor -u thirduser -k picoctf{THIRDSECRETKEY} read

echo "Test: write with name: firstuser, key: picoctf{FIRSTSECRETKEY}"
./stor -u firstuser -k picoctf{FIRSTSECRETKEY} write -f user1file1 'test user input'

echo "Test: write with name: seconduser, key: picoctf{SECONDSECRETKEY}"
./stor -u seconduser -k picoctf{SECONDSECRETKEY} write -f user1file1 'test user input'