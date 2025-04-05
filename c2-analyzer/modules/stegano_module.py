from stegano import lsb
from PIL import Image
import os

def encode_message(image_path, secret_message, output_path):
    try:
        # Open the image file and ensure it's in RGB mode
        img = Image.open(image_path)
        img = img.convert("RGB")
        img.save(image_path)  # Save the image to ensure format is clean

        # Check if the secret message is too long for the image
        if len(secret_message) > (img.width * img.height * 3 // 8):  # LSB can store 1 bit per channel per pixel
            return "Message too long to fit in the image. Please use a shorter message."

        # Encode the message using LSB and save the new image
        lsb.hide(image_path, secret_message).save(output_path)
        return "Message successfully hidden in the image!"

    except Exception as e:
        return f"Error hiding message: {e}"

def decode_message(image_path):
    try:
        # Attempt to reveal the secret message
        result = lsb.reveal(image_path)

        # If message found, return it, else notify that no message was found
        if result:
            return f"Hidden message: {result}"
        else:
            return "No hidden message found in the image."

    except Exception as e:
        # If an error occurs, return the exception message
        return f"Error revealing message: {e}"
