import hashlib
import time
import binascii
import math
import string

#compilation of well known passwords
my_wordlist = "wordlist.txt" #temporary set a file

#example of target's password for demostration only
targetPassword1 = "correcthorsebatterystaple"

#randomWord is in binary string
randomWord = b"iamcute1"

# converts plain text into cipher text using SHA256 algorithm, 
# SHA-2 generates 32 bytes of unique, hash value, or digital fingerprint

# visual presentation of a 32 bytes 
# 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
targetEncrypted = hashlib.sha256(targetPassword1.encode()).hexdigest()

#print("\ntarget's digital fingerprint(SHA256): " + targetEncrypted)

# converts plain text into cipher text using PBKDF2
# Password-Based Key Derivation Function 2 ideal for short and weak passwords 
# With the help of pseudorandom function (sha-2, random, iterations)
derivedKey = hashlib.pbkdf2_hmac("sha256", targetPassword1.encode(), randomWord, 100000)
target_derivedkey = binascii.hexlify(derivedKey).decode()

#print("\n target's digital fingerprint(PBKDF2)" + target_derivedkey)


#attack simulation function for SHA-2 
def AttackTarget_bySha256(wordlist_path, target_hash):
    start = time.time()
    attempts = 0

    #read open wordlist.txt
    with open(wordlist_path, "r", encoding="utf8") as f:
        #read text per line
        for line in f:
            candidate = line.strip()

            #continue if not found
            if not candidate:
                continue
            attempts += 1

            #convert plain text to cipher text in sha256.
            candidateEncrypted = hashlib.sha256(candidate.encode()).hexdigest()

            #when candidate word matches target password
            if candidateEncrypted == target_hash:
                elapsed = (time.time() - start)*1000
                print(elapsed)
                #return the word, number of attempts and time required to crack the password. 
                return True, candidate, attempts, elapsed

    #if no word in the wordlist matches the password return false. 
    return False, None, attempts, (time.time() - start)*1000


#create a function that will calculate the entropy
#measurable signal of unpredictability
#higher the entropy the harder it is for an attacker to guess a secret.
def EntropyBitsCount(targetPassword1):
    #Entropy = L × log2(R)
    #R - poolSize
    #L - passwordsLength
    poolSize = 0
    if any(character.islower() for character in targetPassword1):
        poolSize += 26 #lowercase character
    if any(character.isupper() for character in targetPassword1):
        poolSize += 26 #uppercase character
    if any(character.isdigit() for character in targetPassword1):
        poolSize += 10 #numeric 
    if any(character in string.punctuation for character in targetPassword1):
        poolSize += len(string.punctuation) #special characters
    
    # for any other unicode characters
    if poolSize == 0:
        poolSize = 256
    entropyBits = len(targetPassword1) * math.log2(poolSize)
    return entropyBits

#function
def passwordStrength(entropyBits):
    
        #Aim for at least 60 bits for user facing accounts
        if (entropyBits < 40):
            return 'weak'
        if (entropyBits < 60):
             return 'moderate'
        if (entropyBits < 80):
             return 'strong'
        return 'very strong'

def main():

    #open file that contains the compilation of passwords related to tentative target
    try:
        open(my_wordlist, "r").close()
    #if no file found, create a default wordlist, just update it if you want to customized the dictionary
    except FileNotFoundError:
        with open(my_wordlist, "w", encoding="utf8") as f:
            f.write("password\n123456\nadmin\ncorrecthorsebatterystaple\npassword1234\npasswordgani\n")

    #return result to the user. 
    print("Simulating SHA256 dictionary attack against lab hash")
    found, pw, attempts, elapsed = AttackTarget_bySha256(my_wordlist, targetEncrypted)
    if found:
        print(f"Cracked SHA256 in {attempts} attempts time {elapsed:.3f} msecs password {pw}")
    else:
        print(f"SHA256 not cracked after {attempts} attempts time {elapsed:.3f} msecs")

    # return result of strength of the password
    print(f'{targetPassword1} -> {EntropyBitsCount(targetPassword1):.1f} bits -> {passwordStrength(EntropyBitsCount(targetPassword1))}')


if __name__ == "__main__":
    main()