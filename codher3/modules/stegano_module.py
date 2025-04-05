from stegano import lsb
import os
from PIL import Image

def encode_message(image_path, secret_message, output_path):
    try:
        # Open and save image to ensure format is clean
        img = Image.open(image_path)
        img = img.convert("RGB")
        img.save(image_path)

        lsb.hide(image_path, secret_message).save(output_path)
        return "Message successfully hidden!"
    except Exception as e:
        return f"Error hiding message: {e}"

def decode_message(image_path):
    try:
        result = lsb.reveal(image_path)
        if result:
            return f"Hidden message: {result}"
        else:
            return "No hidden message found."
    except Exception as e:
        return f"Error revealing message: {e}"
