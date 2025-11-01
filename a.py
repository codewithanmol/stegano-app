import streamlit as st
import numpy as np
from PIL import Image
import cv2
import io
import base64
import os
import tempfile
from cryptography.fernet import Fernet
import zipfile
import json
from pydub import AudioSegment
from moviepy.editor import VideoFileClip
import wave
import struct

# Page config
st.set_page_config(
    page_title="SteganMol - Advanced Steganography Tool",
    page_icon="🔒",
    layout="wide"
)

class ImageSteganography:
    @staticmethod
    def encode_image(image, message, password=None):
        if password:
            key = Fernet.generate_key()
            cipher = Fernet(key)
            message = cipher.encrypt(message.encode()).decode()
            message = base64.b64encode(key).decode() + ":" + message
        
        message += "###END###"
        img_array = np.array(image)
        
        if len(img_array.shape) == 3:
            img_array = img_array.reshape(-1)
        else:
            img_array = img_array.flatten()
        
        message_bits = ''.join([format(ord(char), '08b') for char in message])
        
        if len(message_bits) > len(img_array):
            raise ValueError("Message too large for image")
        
        for i in range(len(message_bits)):
            img_array[i] = (img_array[i] & 0xFE) | int(message_bits[i])
        
        return img_array.reshape(np.array(image).shape)
    
    @staticmethod
    def decode_image(image, password=None):
        img_array = np.array(image).flatten()
        message_bits = ''.join([str(pixel & 1) for pixel in img_array])
        
        message = ""
        for i in range(0, len(message_bits), 8):
            byte = message_bits[i:i+8]
            if len(byte) == 8:
                char = chr(int(byte, 2))
                message += char
                if message.endswith("###END###"):
                    message = message[:-9]
                    break
        
        if password and ":" in message:
            key_b64, encrypted_msg = message.split(":", 1)
            key = base64.b64decode(key_b64.encode())
            cipher = Fernet(key)
            message = cipher.decrypt(encrypted_msg.encode()).decode()
        
        return message

class AudioSteganography:
    @staticmethod
    def encode_audio(audio_file, message):
        audio = AudioSegment.from_file(audio_file)
        audio_data = np.array(audio.get_array_of_samples())
        
        message += "###END###"
        message_bits = ''.join([format(ord(char), '08b') for char in message])
        
        if len(message_bits) > len(audio_data):
            raise ValueError("Message too large for audio")
        
        for i in range(len(message_bits)):
            audio_data[i] = (audio_data[i] & 0xFFFE) | int(message_bits[i])
        
        return audio_data, audio.frame_rate, audio.channels
    
    @staticmethod
    def decode_audio(audio_file):
        audio = AudioSegment.from_file(audio_file)
        audio_data = np.array(audio.get_array_of_samples())
        
        message_bits = ''.join([str(sample & 1) for sample in audio_data])
        
        message = ""
        for i in range(0, len(message_bits), 8):
            byte = message_bits[i:i+8]
            if len(byte) == 8:
                char = chr(int(byte, 2))
                message += char
                if message.endswith("###END###"):
                    return message[:-9]
        return message

class TextSteganography:
    @staticmethod
    def encode_text(cover_text, secret_message):
        # Using zero-width characters
        zero_width_chars = ['\u200B', '\u200C', '\u200D', '\u2060']
        
        binary_message = ''.join([format(ord(char), '08b') for char in secret_message])
        binary_message += '1111111111111110'  # End marker
        
        encoded_text = ""
        bit_index = 0
        
        for char in cover_text:
            encoded_text += char
            if bit_index < len(binary_message):
                if binary_message[bit_index] == '1':
                    encoded_text += zero_width_chars[0]
                else:
                    encoded_text += zero_width_chars[1]
                bit_index += 1
        
        return encoded_text
    
    @staticmethod
    def decode_text(encoded_text):
        zero_width_chars = ['\u200B', '\u200C', '\u200D', '\u2060']
        
        binary_message = ""
        for char in encoded_text:
            if char == zero_width_chars[0]:
                binary_message += '1'
            elif char == zero_width_chars[1]:
                binary_message += '0'
        
        # Find end marker
        end_marker = '1111111111111110'
        end_pos = binary_message.find(end_marker)
        if end_pos != -1:
            binary_message = binary_message[:end_pos]
        
        message = ""
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i:i+8]
            if len(byte) == 8:
                message += chr(int(byte, 2))
        
        return message

class EmojiSteganography:
    @staticmethod
    def encode_emoji(message):
        # Map characters to emoji pairs
        emoji_map = {
            '0': '😀😃', '1': '😄😁', '2': '😆😅', '3': '🤣😂',
            '4': '🙂🙃', '5': '😉😊', '6': '😇🥰', '7': '😍🤩',
            '8': '🥳😏', '9': '😒😞', 'a': '😔😟', 'b': '😕🙁',
            'c': '☹️😣', 'd': '😖😫', 'e': '😩🥺', 'f': '😢😭'
        }
        
        binary_message = ''.join([format(ord(char), '08b') for char in message])
        hex_message = hex(int(binary_message, 2))[2:]
        
        emoji_text = ""
        for char in hex_message.lower():
            if char in emoji_map:
                emoji_text += emoji_map[char]
        
        return emoji_text
    
    @staticmethod
    def decode_emoji(emoji_text):
        # Reverse emoji map
        reverse_map = {
            '😀😃': '0', '😄😁': '1', '😆😅': '2', '🤣😂': '3',
            '🙂🙃': '4', '😉😊': '5', '😇🥰': '6', '😍🤩': '7',
            '🥳😏': '8', '😒😞': '9', '😔😟': 'a', '😕🙁': 'b',
            '☹️😣': 'c', '😖😫': 'd', '😩🥺': 'e', '😢😭': 'f'
        }
        
        hex_chars = ""
        i = 0
        while i < len(emoji_text) - 1:
            emoji_pair = emoji_text[i:i+2]
            if emoji_pair in reverse_map:
                hex_chars += reverse_map[emoji_pair]
            i += 2
        
        try:
            binary_message = bin(int(hex_chars, 16))[2:]
            # Pad to multiple of 8
            while len(binary_message) % 8 != 0:
                binary_message = '0' + binary_message
            
            message = ""
            for i in range(0, len(binary_message), 8):
                byte = binary_message[i:i+8]
                if len(byte) == 8:
                    message += chr(int(byte, 2))
            
            return message
        except:
            return "Decoding failed"

def main():
    st.title("🔒 SteganMol - Advanced Steganography Tool")
    st.markdown("Hide and reveal secret messages in images, audio, video, text, and more!")
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    mode = st.sidebar.selectbox(
        "Choose Steganography Type",
        ["Image", "Audio", "Video", "Text", "File", "Emoji", "Network"]
    )
    
    operation = st.sidebar.radio("Operation", ["Encode", "Decode"])
    
    if mode == "Image":
        st.header("🖼️ Image Steganography")
        
        if operation == "Encode":
            st.subheader("Hide Message in Image")
            
            uploaded_file = st.file_uploader("Choose an image", type=['png', 'jpg', 'jpeg'])
            message = st.text_area("Enter secret message")
            use_password = st.checkbox("Use password protection")
            password = st.text_input("Password", type="password") if use_password else None
            
            if uploaded_file and message:
                image = Image.open(uploaded_file)
                st.image(image, caption="Original Image", width=300)
                
                if st.button("Hide Message"):
                    try:
                        encoded_array = ImageSteganography.encode_image(image, message, password)
                        encoded_image = Image.fromarray(encoded_array.astype(np.uint8))
                        
                        # Save to bytes
                        img_buffer = io.BytesIO()
                        encoded_image.save(img_buffer, format='PNG')
                        img_bytes = img_buffer.getvalue()
                        
                        st.success("Message hidden successfully!")
                        st.image(encoded_image, caption="Encoded Image", width=300)
                        st.download_button(
                            "Download Encoded Image",
                            img_bytes,
                            "encoded_image.png",
                            "image/png"
                        )
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        
        else:  # Decode
            st.subheader("Extract Message from Image")
            
            uploaded_file = st.file_uploader("Choose encoded image", type=['png', 'jpg', 'jpeg'])
            use_password = st.checkbox("Image is password protected")
            password = st.text_input("Password", type="password") if use_password else None
            
            if uploaded_file:
                image = Image.open(uploaded_file)
                st.image(image, caption="Encoded Image", width=300)
                
                if st.button("Extract Message"):
                    try:
                        message = ImageSteganography.decode_image(image, password)
                        st.success("Message extracted successfully!")
                        st.text_area("Hidden Message", message, height=100)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
    
    elif mode == "Audio":
        st.header("🎵 Audio Steganography")
        
        if operation == "Encode":
            st.subheader("Hide Message in Audio")
            
            uploaded_file = st.file_uploader("Choose an audio file", type=['wav', 'mp3', 'ogg'])
            message = st.text_area("Enter secret message")
            
            if uploaded_file and message:
                st.audio(uploaded_file)
                
                if st.button("Hide Message"):
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as tmp_file:
                            tmp_file.write(uploaded_file.read())
                            tmp_file.flush()
                            
                            audio_data, frame_rate, channels = AudioSteganography.encode_audio(tmp_file.name, message)
                            
                            # Create new audio file
                            encoded_audio = AudioSegment(
                                audio_data.tobytes(),
                                frame_rate=frame_rate,
                                sample_width=2,
                                channels=channels
                            )
                            
                            output_buffer = io.BytesIO()
                            encoded_audio.export(output_buffer, format="wav")
                            
                            st.success("Message hidden in audio!")
                            st.download_button(
                                "Download Encoded Audio",
                                output_buffer.getvalue(),
                                "encoded_audio.wav",
                                "audio/wav"
                            )
                        
                        os.unlink(tmp_file.name)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        
        else:  # Decode
            st.subheader("Extract Message from Audio")
            
            uploaded_file = st.file_uploader("Choose encoded audio", type=['wav', 'mp3', 'ogg'])
            
            if uploaded_file:
                st.audio(uploaded_file)
                
                if st.button("Extract Message"):
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as tmp_file:
                            tmp_file.write(uploaded_file.read())
                            tmp_file.flush()
                            
                            message = AudioSteganography.decode_audio(tmp_file.name)
                            st.success("Message extracted!")
                            st.text_area("Hidden Message", message, height=100)
                        
                        os.unlink(tmp_file.name)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
    
    elif mode == "Text":
        st.header("📝 Text Steganography")
        
        if operation == "Encode":
            st.subheader("Hide Message in Text")
            
            cover_text = st.text_area("Enter cover text", height=150)
            secret_message = st.text_input("Enter secret message")
            
            if cover_text and secret_message:
                if st.button("Hide Message"):
                    encoded_text = TextSteganography.encode_text(cover_text, secret_message)
                    st.success("Message hidden in text!")
                    st.text_area("Encoded Text (copy this)", encoded_text, height=150)
        
        else:  # Decode
            st.subheader("Extract Message from Text")
            
            encoded_text = st.text_area("Paste encoded text", height=150)
            
            if encoded_text:
                if st.button("Extract Message"):
                    message = TextSteganography.decode_text(encoded_text)
                    st.success("Message extracted!")
                    st.text_input("Hidden Message", message)
    
    elif mode == "Emoji":
        st.header("😀 Emoji Steganography")
        
        if operation == "Encode":
            st.subheader("Hide Message in Emojis")
            
            message = st.text_input("Enter message to hide")
            
            if message:
                if st.button("Generate Emoji Code"):
                    emoji_code = EmojiSteganography.encode_emoji(message)
                    st.success("Message encoded in emojis!")
                    st.text_area("Emoji Code (copy this)", emoji_code, height=100)
        
        else:  # Decode
            st.subheader("Decode Message from Emojis")
            
            emoji_code = st.text_area("Paste emoji code", height=100)
            
            if emoji_code:
                if st.button("Decode Message"):
                    message = EmojiSteganography.decode_emoji(emoji_code)
                    st.success("Message decoded!")
                    st.text_input("Hidden Message", message)
    
    elif mode == "File":
        st.header("📁 File Steganography")
        st.info("Hide files within other files using ZIP containers")
        
        if operation == "Encode":
            st.subheader("Hide File in Container")
            
            container_file = st.file_uploader("Choose container file", type=['jpg', 'png', 'pdf', 'txt'])
            secret_file = st.file_uploader("Choose file to hide")
            
            if container_file and secret_file:
                if st.button("Hide File"):
                    # Create ZIP with both files
                    zip_buffer = io.BytesIO()
                    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                        zip_file.writestr("container", container_file.read())
                        zip_file.writestr("hidden_file", secret_file.read())
                    
                    st.success("File hidden successfully!")
                    st.download_button(
                        "Download Container",
                        zip_buffer.getvalue(),
                        "container.zip",
                        "application/zip"
                    )
        
        else:  # Decode
            st.subheader("Extract Hidden File")
            
            container_file = st.file_uploader("Choose container file", type=['zip'])
            
            if container_file:
                if st.button("Extract Hidden File"):
                    try:
                        with zipfile.ZipFile(container_file) as zip_file:
                            files = zip_file.namelist()
                            if "hidden_file" in files:
                                hidden_data = zip_file.read("hidden_file")
                                st.success("Hidden file found!")
                                st.download_button(
                                    "Download Hidden File",
                                    hidden_data,
                                    "extracted_file",
                                    "application/octet-stream"
                                )
                            else:
                                st.error("No hidden file found")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
    
    elif mode == "Network":
        st.header("🌐 Network Steganography Simulation")
        st.info("Simulate hiding data in network packet headers")
        
        if operation == "Encode":
            st.subheader("Hide Message in Packet")
            
            message = st.text_input("Enter message")
            src_ip = st.text_input("Source IP", "192.168.1.1")
            dst_ip = st.text_input("Destination IP", "192.168.1.100")
            
            if message:
                if st.button("Create Packet"):
                    # Simulate packet creation
                    packet_data = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "hidden_message": base64.b64encode(message.encode()).decode(),
                        "timestamp": "2024-01-01 12:00:00"
                    }
                    
                    packet_json = json.dumps(packet_data, indent=2)
                    st.success("Packet created with hidden message!")
                    st.code(packet_json, language="json")
                    
                    st.download_button(
                        "Download Packet",
                        packet_json,
                        "packet.json",
                        "application/json"
                    )
        
        else:  # Decode
            st.subheader("Extract Message from Packet")
            
            uploaded_file = st.file_uploader("Choose packet file", type=['json'])
            
            if uploaded_file:
                if st.button("Extract Message"):
                    try:
                        packet_data = json.load(uploaded_file)
                        if "hidden_message" in packet_data:
                            message = base64.b64decode(packet_data["hidden_message"]).decode()
                            st.success("Message extracted from packet!")
                            st.text_input("Hidden Message", message)
                        else:
                            st.error("No hidden message found")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
    
    # Footer
    st.markdown("---")
    st.markdown("**SteganMol** - Advanced Steganography Tool | Built with Streamlit")

if __name__ == "__main__":
    main()
import streamlit as st
import numpy as np
from PIL import Image
import cv2
import io
import base64
import os
import tempfile
from cryptography.fernet import Fernet
import zipfile
import json
from pydub import AudioSegment
from moviepy.editor import VideoFileClip
import wave
import struct

# Page config
st.set_page_config(
    page_title="SteganMol - Advanced Steganography Tool",
    page_icon="🔒",
    layout="wide"
)

class ImageSteganography:
    @staticmethod
    def encode_image(image, message, password=None):
        if password:
            key = Fernet.generate_key()
            cipher = Fernet(key)
            message = cipher.encrypt(message.encode()).decode()
            message = base64.b64encode(key).decode() + ":" + message
        
        message += "###END###"
        img_array = np.array(image)
        
        if len(img_array.shape) == 3:
            img_array = img_array.reshape(-1)
        else:
            img_array = img_array.flatten()
        
        message_bits = ''.join([format(ord(char), '08b') for char in message])
        
        if len(message_bits) > len(img_array):
            raise ValueError("Message too large for image")
        
        for i in range(len(message_bits)):
            img_array[i] = (img_array[i] & 0xFE) | int(message_bits[i])
        
        return img_array.reshape(np.array(image).shape)
    
    @staticmethod
    def decode_image(image, password=None):
        img_array = np.array(image).flatten()
        message_bits = ''.join([str(pixel & 1) for pixel in img_array])
        
        message = ""
        for i in range(0, len(message_bits), 8):
            byte = message_bits[i:i+8]
            if len(byte) == 8:
                char = chr(int(byte, 2))
                message += char
                if message.endswith("###END###"):
                    message = message[:-9]
                    break
        
        if password and ":" in message:
            key_b64, encrypted_msg = message.split(":", 1)
            key = base64.b64decode(key_b64.encode())
            cipher = Fernet(key)
            message = cipher.decrypt(encrypted_msg.encode()).decode()
        
        return message

class AudioSteganography:
    @staticmethod
    def encode_audio(audio_file, message):
        audio = AudioSegment.from_file(audio_file)
        audio_data = np.array(audio.get_array_of_samples())
        
        message += "###END###"
        message_bits = ''.join([format(ord(char), '08b') for char in message])
        
        if len(message_bits) > len(audio_data):
            raise ValueError("Message too large for audio")
        
        for i in range(len(message_bits)):
            audio_data[i] = (audio_data[i] & 0xFFFE) | int(message_bits[i])
        
        return audio_data, audio.frame_rate, audio.channels
    
    @staticmethod
    def decode_audio(audio_file):
        audio = AudioSegment.from_file(audio_file)
        audio_data = np.array(audio.get_array_of_samples())
        
        message_bits = ''.join([str(sample & 1) for sample in audio_data])
        
        message = ""
        for i in range(0, len(message_bits), 8):
            byte = message_bits[i:i+8]
            if len(byte) == 8:
                char = chr(int(byte, 2))
                message += char
                if message.endswith("###END###"):
                    return message[:-9]
        return message

class TextSteganography:
    @staticmethod
    def encode_text(cover_text, secret_message):
        # Using zero-width characters
        zero_width_chars = ['\u200B', '\u200C', '\u200D', '\u2060']
        
        binary_message = ''.join([format(ord(char), '08b') for char in secret_message])
        binary_message += '1111111111111110'  # End marker
        
        encoded_text = ""
        bit_index = 0
        
        for char in cover_text:
            encoded_text += char
            if bit_index < len(binary_message):
                if binary_message[bit_index] == '1':
                    encoded_text += zero_width_chars[0]
                else:
                    encoded_text += zero_width_chars[1]
                bit_index += 1
        
        return encoded_text
    
    @staticmethod
    def decode_text(encoded_text):
        zero_width_chars = ['\u200B', '\u200C', '\u200D', '\u2060']
        
        binary_message = ""
        for char in encoded_text:
            if char == zero_width_chars[0]:
                binary_message += '1'
            elif char == zero_width_chars[1]:
                binary_message += '0'
        
        # Find end marker
        end_marker = '1111111111111110'
        end_pos = binary_message.find(end_marker)
        if end_pos != -1:
            binary_message = binary_message[:end_pos]
        
        message = ""
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i:i+8]
            if len(byte) == 8:
                message += chr(int(byte, 2))
        
        return message

class EmojiSteganography:
    @staticmethod
    def encode_emoji(message):
        # Map characters to emoji pairs
        emoji_map = {
            '0': '😀😃', '1': '😄😁', '2': '😆😅', '3': '🤣😂',
            '4': '🙂🙃', '5': '😉😊', '6': '😇🥰', '7': '😍🤩',
            '8': '🥳😏', '9': '😒😞', 'a': '😔😟', 'b': '😕🙁',
            'c': '☹️😣', 'd': '😖😫', 'e': '😩🥺', 'f': '😢😭'
        }
        
        binary_message = ''.join([format(ord(char), '08b') for char in message])
        hex_message = hex(int(binary_message, 2))[2:]
        
        emoji_text = ""
        for char in hex_message.lower():
            if char in emoji_map:
                emoji_text += emoji_map[char]
        
        return emoji_text
    
    @staticmethod
    def decode_emoji(emoji_text):
        # Reverse emoji map
        reverse_map = {
            '😀😃': '0', '😄😁': '1', '😆😅': '2', '🤣😂': '3',
            '🙂🙃': '4', '😉😊': '5', '😇🥰': '6', '😍🤩': '7',
            '🥳😏': '8', '😒😞': '9', '😔😟': 'a', '😕🙁': 'b',
            '☹️😣': 'c', '😖😫': 'd', '😩🥺': 'e', '😢😭': 'f'
        }
        
        hex_chars = ""
        i = 0
        while i < len(emoji_text) - 1:
            emoji_pair = emoji_text[i:i+2]
            if emoji_pair in reverse_map:
                hex_chars += reverse_map[emoji_pair]
            i += 2
        
        try:
            binary_message = bin(int(hex_chars, 16))[2:]
            # Pad to multiple of 8
            while len(binary_message) % 8 != 0:
                binary_message = '0' + binary_message
            
            message = ""
            for i in range(0, len(binary_message), 8):
                byte = binary_message[i:i+8]
                if len(byte) == 8:
                    message += chr(int(byte, 2))
            
            return message
        except:
            return "Decoding failed"

def main():
    st.title("🔒 SteganMol - Advanced Steganography Tool")
    st.markdown("Hide and reveal secret messages in images, audio, video, text, and more!")
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    mode = st.sidebar.selectbox(
        "Choose Steganography Type",
        ["Image", "Audio", "Video", "Text", "File", "Emoji", "Network"]
    )
    
    operation = st.sidebar.radio("Operation", ["Encode", "Decode"])
    
    if mode == "Image":
        st.header("🖼️ Image Steganography")
        
        if operation == "Encode":
            st.subheader("Hide Message in Image")
            
            uploaded_file = st.file_uploader("Choose an image", type=['png', 'jpg', 'jpeg'])
            message = st.text_area("Enter secret message")
            use_password = st.checkbox("Use password protection")
            password = st.text_input("Password", type="password") if use_password else None
            
            if uploaded_file and message:
                image = Image.open(uploaded_file)
                st.image(image, caption="Original Image", width=300)
                
                if st.button("Hide Message"):
                    try:
                        encoded_array = ImageSteganography.encode_image(image, message, password)
                        encoded_image = Image.fromarray(encoded_array.astype(np.uint8))
                        
                        # Save to bytes
                        img_buffer = io.BytesIO()
                        encoded_image.save(img_buffer, format='PNG')
                        img_bytes = img_buffer.getvalue()
                        
                        st.success("Message hidden successfully!")
                        st.image(encoded_image, caption="Encoded Image", width=300)
                        st.download_button(
                            "Download Encoded Image",
                            img_bytes,
                            "encoded_image.png",
                            "image/png"
                        )
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        
        else:  # Decode
            st.subheader("Extract Message from Image")
            
            uploaded_file = st.file_uploader("Choose encoded image", type=['png', 'jpg', 'jpeg'])
            use_password = st.checkbox("Image is password protected")
            password = st.text_input("Password", type="password") if use_password else None
            
            if uploaded_file:
                image = Image.open(uploaded_file)
                st.image(image, caption="Encoded Image", width=300)
                
                if st.button("Extract Message"):
                    try:
                        message = ImageSteganography.decode_image(image, password)
                        st.success("Message extracted successfully!")
                        st.text_area("Hidden Message", message, height=100)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
    
    elif mode == "Audio":
        st.header("🎵 Audio Steganography")
        
        if operation == "Encode":
            st.subheader("Hide Message in Audio")
            
            uploaded_file = st.file_uploader("Choose an audio file", type=['wav', 'mp3', 'ogg'])
            message = st.text_area("Enter secret message")
            
            if uploaded_file and message:
                st.audio(uploaded_file)
                
                if st.button("Hide Message"):
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as tmp_file:
                            tmp_file.write(uploaded_file.read())
                            tmp_file.flush()
                            
                            audio_data, frame_rate, channels = AudioSteganography.encode_audio(tmp_file.name, message)
                            
                            # Create new audio file
                            encoded_audio = AudioSegment(
                                audio_data.tobytes(),
                                frame_rate=frame_rate,
                                sample_width=2,
                                channels=channels
                            )
                            
                            output_buffer = io.BytesIO()
                            encoded_audio.export(output_buffer, format="wav")
                            
                            st.success("Message hidden in audio!")
                            st.download_button(
                                "Download Encoded Audio",
                                output_buffer.getvalue(),
                                "encoded_audio.wav",
                                "audio/wav"
                            )
                        
                        os.unlink(tmp_file.name)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        
        else:  # Decode
            st.subheader("Extract Message from Audio")
            
            uploaded_file = st.file_uploader("Choose encoded audio", type=['wav', 'mp3', 'ogg'])
            
            if uploaded_file:
                st.audio(uploaded_file)
                
                if st.button("Extract Message"):
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as tmp_file:
                            tmp_file.write(uploaded_file.read())
                            tmp_file.flush()
                            
                            message = AudioSteganography.decode_audio(tmp_file.name)
                            st.success("Message extracted!")
                            st.text_area("Hidden Message", message, height=100)
                        
                        os.unlink(tmp_file.name)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
    
    elif mode == "Text":
        st.header("📝 Text Steganography")
        
        if operation == "Encode":
            st.subheader("Hide Message in Text")
            
            cover_text = st.text_area("Enter cover text", height=150)
            secret_message = st.text_input("Enter secret message")
            
            if cover_text and secret_message:
                if st.button("Hide Message"):
                    encoded_text = TextSteganography.encode_text(cover_text, secret_message)
                    st.success("Message hidden in text!")
                    st.text_area("Encoded Text (copy this)", encoded_text, height=150)
        
        else:  # Decode
            st.subheader("Extract Message from Text")
            
            encoded_text = st.text_area("Paste encoded text", height=150)
            
            if encoded_text:
                if st.button("Extract Message"):
                    message = TextSteganography.decode_text(encoded_text)
                    st.success("Message extracted!")
                    st.text_input("Hidden Message", message)
    
    elif mode == "Emoji":
        st.header("😀 Emoji Steganography")
        
        if operation == "Encode":
            st.subheader("Hide Message in Emojis")
            
            message = st.text_input("Enter message to hide")
            
            if message:
                if st.button("Generate Emoji Code"):
                    emoji_code = EmojiSteganography.encode_emoji(message)
                    st.success("Message encoded in emojis!")
                    st.text_area("Emoji Code (copy this)", emoji_code, height=100)
        
        else:  # Decode
            st.subheader("Decode Message from Emojis")
            
            emoji_code = st.text_area("Paste emoji code", height=100)
            
            if emoji_code:
                if st.button("Decode Message"):
                    message = EmojiSteganography.decode_emoji(emoji_code)
                    st.success("Message decoded!")
                    st.text_input("Hidden Message", message)
    
    elif mode == "File":
        st.header("📁 File Steganography")
        st.info("Hide files within other files using ZIP containers")
        
        if operation == "Encode":
            st.subheader("Hide File in Container")
            
            container_file = st.file_uploader("Choose container file", type=['jpg', 'png', 'pdf', 'txt'])
            secret_file = st.file_uploader("Choose file to hide")
            
            if container_file and secret_file:
                if st.button("Hide File"):
                    # Create ZIP with both files
                    zip_buffer = io.BytesIO()
                    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                        zip_file.writestr("container", container_file.read())
                        zip_file.writestr("hidden_file", secret_file.read())
                    
                    st.success("File hidden successfully!")
                    st.download_button(
                        "Download Container",
                        zip_buffer.getvalue(),
                        "container.zip",
                        "application/zip"
                    )
        
        else:  # Decode
            st.subheader("Extract Hidden File")
            
            container_file = st.file_uploader("Choose container file", type=['zip'])
            
            if container_file:
                if st.button("Extract Hidden File"):
                    try:
                        with zipfile.ZipFile(container_file) as zip_file:
                            files = zip_file.namelist()
                            if "hidden_file" in files:
                                hidden_data = zip_file.read("hidden_file")
                                st.success("Hidden file found!")
                                st.download_button(
                                    "Download Hidden File",
                                    hidden_data,
                                    "extracted_file",
                                    "application/octet-stream"
                                )
                            else:
                                st.error("No hidden file found")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
    
    elif mode == "Network":
        st.header("🌐 Network Steganography Simulation")
        st.info("Simulate hiding data in network packet headers")
        
        if operation == "Encode":
            st.subheader("Hide Message in Packet")
            
            message = st.text_input("Enter message")
            src_ip = st.text_input("Source IP", "192.168.1.1")
            dst_ip = st.text_input("Destination IP", "192.168.1.100")
            
            if message:
                if st.button("Create Packet"):
                    # Simulate packet creation
                    packet_data = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "hidden_message": base64.b64encode(message.encode()).decode(),
                        "timestamp": "2024-01-01 12:00:00"
                    }
                    
                    packet_json = json.dumps(packet_data, indent=2)
                    st.success("Packet created with hidden message!")
                    st.code(packet_json, language="json")
                    
                    st.download_button(
                        "Download Packet",
                        packet_json,
                        "packet.json",
                        "application/json"
                    )
        
        else:  # Decode
            st.subheader("Extract Message from Packet")
            
            uploaded_file = st.file_uploader("Choose packet file", type=['json'])
            
            if uploaded_file:
                if st.button("Extract Message"):
                    try:
                        packet_data = json.load(uploaded_file)
                        if "hidden_message" in packet_data:
                            message = base64.b64decode(packet_data["hidden_message"]).decode()
                            st.success("Message extracted from packet!")
                            st.text_input("Hidden Message", message)
                        else:
                            st.error("No hidden message found")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
    
    # Footer
    st.markdown("---")
    st.markdown("**SteganMol** - Advanced Steganography Tool | Built with Streamlit")

if __name__ == "__main__":
    main()
