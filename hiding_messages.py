import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography with AES Encryption")

        # GUI components
        self.label = tk.Label(root, text="Enter the message to be encoded:")
        self.message_entry = tk.Entry(root, width=50)
        self.browse_button = tk.Button(root, text="Browse Image", command=self.browse_image)
        self.encode_button = tk.Button(root, text="Encode", command=self.encode_message)
        self.decode_button = tk.Button(root, text="Decode", command=self.decode_message)
        self.download_button = tk.Button(root, text="Download Image", command=self.download_image)
        self.result_label = tk.Label(root, text="Result: ")

        # Layout management
        self.label.pack()
        self.message_entry.pack()
        self.browse_button.pack()
        self.encode_button.pack()
        self.decode_button.pack()
        self.download_button.pack()
        self.result_label.pack()

    def browse_image(self):
        file_path = filedialog.askopenfilename(title="Select Image File", filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if file_path:
            self.image_path = file_path
            self.result_label.config(text=f"Selected Image: {file_path}")

    def encode_message(self):
        if hasattr(self, 'image_path'):
            message = self.message_entry.get()
            if message:
                encrypted_message = self.encrypt_message(message)
                self.hide_message_in_image(encrypted_message)
                self.result_label.config(text="Message encoded successfully!")
            else:
                self.result_label.config(text="Please enter a message.")
        else:
            self.result_label.config(text="Please select an image.")

    def decode_message(self):
        if hasattr(self, 'image_path'):
            decrypted_message = self.retrieve_hidden_message_from_image()
            if decrypted_message:
                self.result_label.config(text=f"Decoded Message: {decrypted_message}")
            else:
                self.result_label.config(text="No hidden message found.")
        else:
            self.result_label.config(text="Please select an image.")

    def encrypt_message(self, message):
        # Generate a random AES key
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC)

        # Pad the message to be a multiple of block size
        block_size = AES.block_size
        padded_message = message.encode('utf-8') + b'\0' * (block_size - len(message) % block_size)

        # Encrypt the padded message with AES
        encrypted_message = cipher.encrypt(padded_message)

        # Save the AES key and initialization vector (IV) in the class for later decryption
        self.key = key
        self.iv = cipher.iv

        return encrypted_message

    def hide_message_in_image(self, encrypted_message):
        # Open the image
        img = Image.open(self.image_path)

        # Convert the encrypted message to binary
        binary_message = ''.join(format(byte, '08b') for byte in encrypted_message)

        data_index = 0

        # Iterate over each pixel
        for x in range(img.width):
            for y in range(img.height):
                pixel = list(img.getpixel((x, y)))

                # Modify the least significant bit of each color component
                for i in range(3):
                    if data_index < len(binary_message):
                        pixel[i] = pixel[i] & ~1 | int(binary_message[data_index])
                        data_index += 1

                # Update the pixel in the image
                img.putpixel((x, y), tuple(pixel))

        # Save the encoded image
        img.save("encoded_image.png")

    def decrypt_message(self, encrypted_message):
     cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)

    # Decrypt the message with AES
     decrypted_message = cipher.decrypt(encrypted_message)

    # Unpad the message manually
     decrypted_message = decrypted_message.rstrip(b"\0")

    # Convert bytes to string
     symbolic_message = decrypted_message.decode('utf-8', errors='replace')

     return symbolic_message


    def retrieve_hidden_message_from_image(self):
        # Open the encoded image
        img = Image.open("encoded_image.png")

        binary_message = ''

        # Iterate over each pixel
        for x in range(img.width):
            for y in range(img.height):
                pixel = list(img.getpixel((x, y)))

                # Extract the least significant bit of each color component
                for i in range(3):
                    binary_message += bin(pixel[i])[-1]

        # Convert binary message to bytes
        encrypted_message = bytes([int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8)])

        # Decrypt the hidden message
        decrypted_message = self.decrypt_message(encrypted_message)

        return decrypted_message

    def download_image(self):
        if hasattr(self, 'image_path'):
            # Ask user for the directory to save the image
            save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])

            if save_path:
                # Copy the image to the specified directory
                import shutil
                shutil.copy("encoded_image.png", save_path)
                self.result_label.config(text=f"Image saved to {save_path}")
            else:
                self.result_label.config(text="Image not saved. Please provide a valid directory.")
        else:
            self.result_label.config(text="Please select an image.")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
