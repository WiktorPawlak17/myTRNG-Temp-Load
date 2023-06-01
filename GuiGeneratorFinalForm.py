import tkinter as tk
from tkinter import filedialog
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from pyspectator.processor import Cpu
import time

def myTRNG(SIZE = 1024):
    SIZE = SIZE * 8
    enable = True
    actualBitStream = ''
    while(enable):
        CPU = Cpu(monitoring_latency=1)  
        seed = int(CPU.load)
        actualSeed = ''
        temp = int(CPU.temperature)
        for i in range(7):
            seed = (13*int(seed)+3*temp)%256    
            actualSeed += str(bin(seed))[2:]
        if(len(actualBitStream) >= SIZE):
            actualBitStream = actualBitStream[0:SIZE]
            enable = False
        else :
            actualBitStream += actualSeed
    return int(actualBitStream,2).to_bytes(((len(actualBitStream) + 7)) //8,'big')
def getTheTRNG(SIZE):
    number = myTRNG(SIZE)
    return(number)

class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Wiktor Pawlak Podpis Cyfrowy")

        self.file_label = tk.Label(root, text="Plik:")
        self.file_label.grid(row=0, column=0, padx=10, pady=10)

        self.file_entry = tk.Entry(root, width=30)
        self.file_entry.grid(row=0, column=1, padx=10, pady=10)

        self.browse_button = tk.Button(root, text="Szukaj", command=self.browse_file)
        self.browse_button.grid(row=0, column=2, padx=10, pady=10)

        self.sign_button = tk.Button(root, text="Podpisz", command=self.sign_file)
        self.sign_button.grid(row=1, column=0, padx=10, pady=10)

        self.verify_button = tk.Button(root, text="Zwefyfikuj", command=self.verify_signature)
        self.verify_button.grid(row=1, column=1, padx=10, pady=10)

        self.result_button = tk.Button(root, text="Rezultat: Nie zweryfikowany", state=tk.DISABLED)
        self.result_button.grid(row=2, column=1, padx=10, pady=10)

        self.private_key = RSA.generate(1024,myTRNG)
        self.public_key = self.private_key.publickey()

    def browse_file(self):
        filepath = filedialog.askopenfilename(initialdir="/", title="Wybierz Plik", filetypes=(("All Files", "*.*"),))
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(tk.END, filepath)

    def sign_file(self):
        filepath = self.file_entry.get()

        with open(filepath, "rb") as file:
            file_contents = file.read()

        hash_object = SHA1.new(file_contents)

        private_key = self.private_key
        signer = pkcs1_15.new(private_key)
        signature = signer.sign(hash_object)

        signature_file = filepath + ".sig"
        with open(signature_file, "wb") as file:
            file.write(signature)

        print("Udało się podpisać plik.")
        print("Zapisano do :", signature_file)

    def verify_signature(self):
        filepath = self.file_entry.get()
        signature_file = filepath + ".sig"

       
        with open(filepath, "rb") as file:
            file_contents = file.read()

        with open(signature_file, "rb") as file:
            signature = file.read()

        hash_object = SHA1.new(file_contents)
        public_key = self.public_key
        verifier = pkcs1_15.new(public_key)
        try:
            verifier.verify(hash_object, signature)
            self.result_button.config(text="Rezultat: Poprawny", bg="green")
        except (ValueError, TypeError):
            self.result_button.config(text="Rezultat: Niepoprawny", bg="red")

root = tk.Tk()
app = DigitalSignatureApp(root)
root.mainloop()

