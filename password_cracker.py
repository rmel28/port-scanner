#password hacker 

#-----Key concpets-----
#Hashing - Converting an input of any length into a fixed size string of text using an algorithm
#input(message to be hashed) + Hash function(Algorithm) = Hash Value(output)
#Qualities: Uniqiness, secure, speed
#Encoding- Converting text into a format that computers can understand
#Byte sequence- serious of bytes where each byte is data (ASCII Values)

#-----Importance-----
#Helps you show the strength of passwords
#Allows you to think like a hacker which helps you to be able to defend against them 

#https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/Ashley-Madison.txt
#database of leaked passwords

import hashlib

password_filename = "/Users/ryanmelody/Desktop/Ashley-Madison.txt"

password = "booomer" #target password just for educatioanl use usally we would not know it

encode_password = password.encode("utf-8") #turning the password into bytes 'booomer' -> b'boomer' showing it is a byte string

password_hash = hashlib.md5(encode_password.strip()).hexdigest() #strips and hashes the byte string 32 character hex -> 71b5d12f91a1ef0370e993d55b2fa7ac - hashlib is the algorithm stuff for this

pass_file = open(password_filename, "r")

for word in pass_file:
    encode_word = word.encode("utf-8") #converts words from file into byte string
    encode_hash = hashlib.md5(encode_word.strip()).hexdigest() #strips and hashes each word from the file 

    if password_hash == encode_hash: #looking for a match of the hashes
        print("This three-letter agency has been hacked. The password was " + word.strip())
        quit()

pass_file.close()

print("The three-letter agency has a strong password")