import streamlit as st
import pandas
from csv import writer
import string

udf = pandas.read_csv("./database.csv")
kdf = pandas.read_csv("./keystore.csv")


def cipher(cipherVal, word):
    """
    Creates encoded data,  use only for MASTER and PUBLIC key generation.
    :param cipherVal: Integar used in encoding
    :param word: Word to be encoded
    :return: Encoded word in form of list
    """
    s1 = list(string.digits + string.ascii_letters + string.punctuation)
    d = range(0, len(s1), cipherVal)
    s2 = [s1[i] for i in d]
    return [s2.index(w) if w in s2 else s1.index(w) for w in word]


def secretDict():
    """
    Create a Secret Dictionary
    """
    values = ["z", "e", "d", "t", "c", "p", "h", "s", "a", "n"]
    alphabets = list(string.ascii_lowercase)
    punct = list(string.punctuation)[:26]
    num = list(string.digits)
    secretdict = {k: v for (k, v) in zip(alphabets, punct)}
    secretdict[" "] = "{"
    for i in range(len(num)):
        secretdict[str(i)] = values[i]
    return secretdict


def csvWriter(path, data):
    with open(path, "a+", newline='') as file:
        csvwriter = writer(file)
        csvwriter.writerow(data)


def m_p_key(uname, paswrd):
    """
    Generates Master key and Public key, paswrd must be larger than uname
    :param uname: Username
    :param paswrd: Password
    :return: MASTER KEY, PUBLIC KEY
    """
    U = cipher(cipherVal=2, word=uname)
    P = cipher(cipherVal=2, word=paswrd)
    P.reverse()
    while len(U) != len(P):
        U.append(1)
    OMK = [(U[i] * P[i]) for i in range(len(U))]
    PK = sum(OMK)
    MK = int("".join(map(str, OMK)))
    return MK, PK


def encryption(key, text):
    """
    Returns encrypted text with secret key at end.
    :param key: Key
    :param text: Text to be encrypted
    :return: Encrypted text
    """
    eDict = secretDict()
    e = []
    for i in text.lower()+str(key):
        e.append(eDict[i])
    val = ''.join([str(j) for j in e])
    return val


def decryption(key, encrypt_text):
    """
    Gives Decrypted text
    :param key: Key
    :param encrypt_text: Encrypted Text
    :return: Decrypted Text
    """
    dDict = secretDict()
    dkey = []
    for i in str(key):
        for ke, va in dDict.items():
            if i == ke:
                dkey.append(va)
    lkey = ''.join([str(di) for di in dkey])
    d = []
    if str(lkey) == encrypt_text[-len(str(key)):]:
        for k in encrypt_text:
            for key, value in dDict.items():
                if k == value:
                    d.append(key)
    else:
        st.error("Wrong key")
    return ''.join([str(e) for e in d])


def main():
    st.title("A Lightweight Secure Data Sharing Scheme for Mobile Computing")

    menu = ["Home", "Login", "SignUp"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        st.subheader("New member please SignUp and existing member please login to continue.")

    elif choice == "Login":
        st.subheader("Enter your login details. . . . ")
        uname = st.text_input("Username")
        pword = st.text_input("Password", type='password')
        if st.checkbox("Login"):
            cpword = udf.loc[udf["Username"] == uname, "Password"][0]
            if pword == cpword:
                st.success("Login Success")
                task = st.selectbox("Task", ["Encrypt a message", "Decrypt a message"])
                if task == "Encrypt a message":
                    text = st.text_input("InputText to be encrypted")
                    pkey = kdf.loc[kdf["Username"] == uname, "PublicKey"][0]
                    st.write("Share your key only to the designated person. Key= "+str(pkey))
                    etext = encryption(key=pkey, text=text)
                    st.success(etext)
                elif task == "Decrypt a message":
                    dtext = st.text_input("InputText to be encrypted")
                    dkey = st.text_input("Enter your Key")
                    dectext = decryption(key=str(dkey), encrypt_text=dtext)
                    st.success(dectext)
            else:
                st.warning("Incorrect Username/Password")

    elif choice == "SignUp":
        st.header("Enter your desired username and password")
        suname = st.text_input("Enter Username")
        spword = st.text_input("Enter Password")
        if st.button("SignUP"):
            if suname in udf["Username"].values:
                st.error("Username already exist")
            else:
                st.write("Generating Your key.")
                csvWriter(path="./database.csv", data=[suname, spword])
                MK, PK = m_p_key(uname=suname, paswrd=spword)
                csvWriter(path="./keystore.csv", data=[suname, MK, PK])
                st.write("Your Key" + str(PK))
                st.success("Welcome")


if __name__ == '__main__':
    main()
