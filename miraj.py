import tkinter as tk
import hashlib

def encrypt_message():
    global original_message, hashed_signature_first_gui
    message = message_entry.get()
    signature = signature_entry.get()
    key = key_entry.get().encode('utf-8')

    original_message = message  # Store the original message

    # Hashing the message, signature, and key using SHA-256
    hashed_message = hashlib.sha256(message.encode('utf-8')).hexdigest()
    hashed_signature_first_gui = hashlib.sha256(signature.encode('utf-8')).hexdigest()
    hashed_key = hashlib.sha256(key).hexdigest()

    # Display encrypted message and signature in the first GUI
    encrypted_message_text.delete(1.0, tk.END)
    encrypted_message_text.insert(tk.END, hashed_message)

    
    # Enable the Send button after encryption
    send_button.config(state=tk.NORMAL)

def send_data():
    encrypted_message = encrypted_message_text.get(1.0, tk.END)
    

    second_gui = tk.Toplevel(root, bg="lightgreen")
    second_gui.title("Second interface")

    received_message_label = tk.Label(second_gui, text="Encrypted Message:")
    received_message_label.pack()
    received_message_text = tk.Text(second_gui,borderwidth=3, height=2, width=30)
    received_message_text.insert(tk.END, encrypted_message)
    received_message_text.pack()

    

    def decrypt_and_verify():
        entered_key = decryption_key_entry.get().encode('utf-8')
        entered_key_hash = hashlib.sha256(entered_key).hexdigest()

        if entered_key_hash == hashlib.sha256(key_entry.get().encode('utf-8')).hexdigest():
            decrypted_message = original_message  # Retrieve the original message
            decrypted_message_label.config(text=f"Decrypted Message: {decrypted_message}")
        else:
            decrypted_message_label.config(text="Wrong Key!")

    def verify_signature():
        auth_key = signature_entry.get()
        authkey_true="miraji"
        if auth_key == authkey_true:
            verify_result_label.config(text="Signature match successful")
        else:
            verify_result_label.config(text="Signature doesn't match")

    decryption_key_label = tk.Label(second_gui, text="Enter Key to Decrypt:")
    decryption_key_label.pack()
    decryption_key_entry = tk.Entry(second_gui,borderwidth=3, show="*")
    decryption_key_entry.pack()

    
    verify_button = tk.Button(second_gui, text="Verify",bg='black',fg='white', command=verify_signature)
    verify_button.pack()
    
    decrypt_button = tk.Button(second_gui,bg='blue',fg='white',text="Decrypt", command=decrypt_and_verify)
    decrypt_button.pack()

    decrypted_message_label = tk.Label(second_gui, text="", bg="lightgreen")
    decrypted_message_label.pack()

    verify_result_label = tk.Label(second_gui, text="")
    verify_result_label.pack()

root = tk.Tk()
root.title("First GUI")

title_label = tk.Label(root, text="Name of Student: MIRAJI TUMAI SEMWANZA ")
title_label.pack()

registration_label = tk.Label(root, text="Registration Number: 2102302226701 ")
registration_label.pack()

message_label = tk.Label(root, text="Enter Message: ")
message_label.pack()
message_entry = tk.Entry(root,borderwidth=3)
message_entry.pack()

key_label = tk.Label(root, text="Enter Key:")
key_label.pack()
key_entry = tk.Entry(root, borderwidth=3,show="*")
key_entry.pack()

encrypt_button = tk.Button(root, text="Encrypt",bg='black',fg='white', command=encrypt_message)
encrypt_button.pack()

signature_label = tk.Label(root, text="Enter Signature:")
signature_label.pack()
signature_entry = tk.Entry(root,borderwidth=3)
signature_entry.pack()

encrypted_message_label = tk.Label(root, text="Encrypted Message:")
encrypted_message_label.pack()
encrypted_message_text = tk.Text(root, height=2, width=30)
encrypted_message_text.pack()



send_button = tk.Button(root, text="TUMA DATA", bg='green',fg='black',command=send_data, state=tk.DISABLED)
send_button.pack()

root.mainloop()