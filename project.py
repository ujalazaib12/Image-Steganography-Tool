from tkinter import *
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
import os
from stegano import lsb
from Crypto.Cipher import AES
import base64
import qrcode
from pyzbar.pyzbar import decode

# Padding for AES block size
def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    return text[:-ord(text[-1])]

def generate_aes_key():
    return os.urandom(16)

def encrypt_aes(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_message = base64.b64encode(cipher.encrypt(pad(message).encode()))
    return encrypted_message

def decrypt_aes(encrypted_message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = unpad(cipher.decrypt(base64.b64decode(encrypted_message)).decode())
    return decrypted_message

def DecryptAES():
    # Ask user for encrypted text first
    encrypted_text = simpledialog.askstring("Encrypted Text", "Enter the encrypted text (base64 encoded):")
    if not encrypted_text:
        messagebox.showerror("Error", "Encrypted text cannot be empty.")
        return

    # Ask user for decryption key
    key_hex = simpledialog.askstring("Decryption Key", "Enter the decryption key:")
    if not key_hex:
        messagebox.showerror("Error", "Decryption key cannot be empty.")
        return

    try:
        # Convert the decryption key from hexadecimal to bytes
        key = bytes.fromhex(key_hex)
        
        # Decode the encrypted text from base64
        encrypted_message = base64.b64decode(encrypted_text)

        # Decrypt the message using AES
        decrypted_message = decrypt_aes(encrypted_message, key)
        
        # Show the decrypted message in the text box
        text1.delete(1.0, END)
        text1.insert(END, decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {e}")

def showimage():
    global filename
    filename = filedialog.askopenfilename(
        initialdir=os.getcwd(),
        title='Select Image File',
        filetypes=[("PNG file", "*.png"), ("JPG File", "*.jpg"), ("All file", "*.*")]
    )

    if not filename or not os.path.isfile(filename):
        messagebox.showerror("Error", "Invalid file selected.")
        return

    try:
        img = Image.open(filename).convert("RGB")
        img = img.resize((250, 250), Image.Resampling.LANCZOS)
        img = ImageTk.PhotoImage(img)
        lbl.configure(image=img, width=250, height=250)
        lbl.image = img
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open image: {e}")

def Hide():
    global secret
    message = text1.get(1.0, END).strip()
    if not message:
        messagebox.showerror("Error", "No message to encode.")
        return

    key = generate_aes_key()
    encrypted_message = encrypt_aes(message, key)

    img = Image.open(filename)
    secret = lsb.hide(img, encrypted_message.decode())
    save_option = messagebox.askyesno("Save Image", "Do you want to overwrite the original image?")
    if save_option:
        secret.save(filename)
        messagebox.showinfo("Image Saved", f"Image overwritten at {filename}\nDecryption Key: {key.hex()}")
    else:
        save()
        messagebox.showinfo("Decryption Key", f"Save this key to decrypt later: {key.hex()}")

def Show():
    key_hex = simpledialog.askstring("Decryption Key", "Enter the decryption key:")
    if not key_hex:
        messagebox.showerror("Error", "Decryption key cannot be empty.")
        return

    try:
        key = bytes.fromhex(key_hex)
        clear_message = lsb.reveal(filename)
        if clear_message:
            decrypted_message = decrypt_aes(clear_message.encode(), key)
            text1.delete(1.0, END)
            text1.insert(END, decrypted_message)
        else:
            messagebox.showerror("Error", "No message found.")
    except Exception:
        messagebox.showerror("Error", "Incorrect key or corrupted data.")

def save():
    if 'secret' not in globals():
        messagebox.showerror("Error", "No hidden data found to save.")
        return

    save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG file", "*.png")])
    if save_path:
        try:
            secret.convert("RGB").save(save_path)
            messagebox.showinfo("Image Saved", f"Image saved as {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save image: {e}")

def generate_qr_code(message):
    qr = qrcode.make(message)
    qr_image = qr.convert("RGB")
    return qr_image

def HideQRCode():
    message = text1.get(1.0, END).strip()
    if not message:
        messagebox.showerror("Error", "No message to encode in QR Code.")
        return

    key = generate_aes_key()
    encrypted_message = encrypt_aes(message, key)

    qr_code = generate_qr_code(encrypted_message.decode())
    qr_code = qr_code.resize((150, 150), Image.Resampling.LANCZOS)  # Increase size of QR code

    img = Image.open(filename).convert("RGB")
    img.paste(qr_code, (50, 50))  # Paste the QR code at a specific location (x=50, y=50)

    save_path = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("JPEG file", "*.jpg"), ("PNG file", "*.png")])
    if save_path:
        img.save(save_path)
        messagebox.showinfo("QR Code Hidden", f"QR Code saved to {save_path}\nDecryption Key: {key.hex()}")

def ExtractQRCode():
    try:
        img = Image.open(filename).convert("RGB")
        # Extract the QR Code region (same as pasted location: x=50, y=50, size=150x150)
        qr_region = img.crop((50, 50, 200, 200))
        
        # Decode QR code
        qr_data = decode(qr_region)
        if not qr_data:
            messagebox.showerror("Error", "No QR Code found in the specified region.")
            return

        encrypted_message = qr_data[0].data.decode()  # Extract data from QR Code
        
        # Ask for the decryption key
        key_hex = simpledialog.askstring("Decryption Key", "Enter the decryption key:")
        if not key_hex:
            messagebox.showerror("Error", "Decryption key cannot be empty.")
            return

        key = bytes.fromhex(key_hex)
        decrypted_message = decrypt_aes(encrypted_message, key)

        # Display the decrypted message
        text1.delete(1.0, END)
        text1.insert(END, decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to extract or decrypt QR Code: {e}")

root = Tk()
root.title("Steganography - Hide a Secret Text Message in an Image")
root.geometry("760x600")
root.resizable(False, False)
root.configure(bg="#2f4155")

# Icon
image_icon = PhotoImage(file="E:/anime pic/nero.png")
root.iconphoto(False, image_icon)

# Logo
logo = PhotoImage(file="E:/anime pic/nero.png")
Label(root, image=logo, bg="#2f4155").place(x=10, y=0)

Label(root, text="IS LAB PROJECT", bg="#2f4155", fg="white", font="arial 25 bold").place(x=120, y=20)

# First Frame
f = Frame(root, bd=3, bg="black", width=340, height=280, relief=GROOVE)
f.place(x=10, y=80)

lbl = Label(f, bg="black")
lbl.place(x=0, y=0, width=340, height=280)

# Second Frame
frame2 = Frame(root, bd=3, bg="black", width=340, height=280, relief=GROOVE)
frame2.place(x=370, y=80)

text1 = Text(frame2, font="Roboto 15", bg="white", fg="black", relief=GROOVE, wrap=WORD)
text1.place(x=0, y=0, width=320, height=280)

scrollbar1 = Scrollbar(frame2)
scrollbar1.place(x=320, y=0, height=300)
scrollbar1.configure(command=text1.yview)
text1.configure(yscrollcommand=scrollbar1.set)

# Third Frame
frame3 = Frame(root, bd=3, bg="#2f4155", width=730, height=100, relief=GROOVE)
frame3.place(x=10, y=370)

Button(frame3, text="Open Image", width=15, height=2, font="arial 12 bold", command=showimage).place(x=20, y=30)
Button(frame3, text="Save Image", width=15, height=2, font="arial 12 bold", command=save).place(x=180, y=30)
Button(frame3, text="Hide Text", width=15, height=2, font="arial 12 bold", command=Hide).place(x=340, y=30)
Button(frame3, text="Show Text", width=15, height=2, font="arial 12 bold", command=Show).place(x=500, y=30)

# Fourth Frame for QR Code Functionality
frame4 = Frame(root, bd=3, bg="#2f4155", width=730, height=100, relief=GROOVE)
frame4.place(x=10, y=480)

Button(frame4, text="Hide QR Code", width=15, height=2, font="arial 12 bold", command=HideQRCode).place(x=20, y=30)
Button(frame4, text="Extract QR Code", width=15, height=2, font="arial 12 bold", command=ExtractQRCode).place(x=180, y=30)

root.mainloop()

