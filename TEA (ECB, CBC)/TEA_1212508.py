from PIL import Image

"""
Name: Qusay Taradeh
UID: 1212508
Date: MAY 2024
"""
"""========================================TEA (ECB, CBC)========================================"""


def split_into_blocks(text):
    """Split the text into blocks of 64-bit
    Parameters
    text: The text to be split
    encoding: The encoding and decoding of the text"""
    blocks = []
    # Converting the text to bytes
    text_bytes = bytes(text, 'latin-1')
    text_bytes = text_bytes.hex()  # replacing with hex values instead of string values

    # Splitting the bytes into blocks of 64-bit (8-Byte)
    for i in range(0, len(text_bytes), 16):
        block = text_bytes[i:i + 16]
        block = block.zfill(16)
        blocks.append(block)

    return blocks


''''Tiny Encryption and Decryption Algorithms'''


def tea(key, block, enc_dec):
    """
    TEA EN/DECRYPTION Parameters:
    key - The key to be used for encryption/decryption
    block - The block to be used for encryption/decryption
    enc_dec - The encryption/decryption algorithm to be used
    """
    # Splitting 128-bit key into 4 32-bit keys
    k0 = key[0:8]
    k1 = key[8:16]
    k2 = key[16:24]
    k3 = key[24:32]

    # Splitting the block into left and right halves i.e(L, R)
    left = block[:len(block) // 2]  # left half (L) which is from index 0 to the middle index
    right = block[len(block) // 2:]  # right half (R) which is from middle index to last index
    delta = 0x9E3779B9  # constant delta for the algorithm

    # Converting keys and halves into integers
    k0 = int(k0, 16)
    k1 = int(k1, 16)
    k2 = int(k2, 16)
    k3 = int(k3, 16)
    left = int(left, 16)
    right = int(right, 16)

    if enc_dec == "Encrypt":  # Encryption mode
        total_sum = 0
        for i in range(32):
            total_sum = (total_sum + delta) % (2 ** 32)
            total_sum %= 2 ** 32
            left = (left + (((right << 4) + k0) ^ (right + total_sum) ^ ((right >> 5) + k1))) % (2 ** 32)
            right = (right + (((left << 4) + k2) ^ (left + total_sum) ^ ((left >> 5) + k3))) % (2 ** 32)

    elif enc_dec == "Decrypt":  # Decryption mode
        total_sum = (delta << 5) % (2 ** 32)
        for i in range(32):
            right = (right - (((left << 4) + k2) ^ (left + total_sum) ^ ((left >> 5) + k3))) % (2 ** 32)
            left = (left - (((right << 4) + k0) ^ (right + total_sum) ^ ((right >> 5) + k1))) % (2 ** 32)
            total_sum = (total_sum - delta) % (2 ** 32)

    # Converting back to hex string
    left_hex = hex(left)[2:]  # to strip the '0x' prefix
    right_hex = hex(right)[2:]  # to strip the '0x' prefix

    # Concatenating two halves into ciphertext/plaintext again after encrypting/decrypting them
    result_block = left_hex + right_hex
    return result_block


def tea_ecb():
    """TEA-ECB mode function"""
    print("\n================TEA Electronic Code Book(TEA-ECB) Mode================")

    while True:  # loop to choose encrypt/decrypt and hold all other required inputs
        print("Choose what you want:\n1. Encrypt.\n2. Decrypt.\n3. Exit.\n")

        option = input("Enter your choice: ")
        if option == "1" or option == "2":  # Encrypt/Decrypt mode

            while True:     # loop to hold the hex value of the key with correct form
                key = input("Enter your key in hex format (128-bit, 32 hex characters): ")  # user key
                if len(key) != 32:
                    print("Key must be 32 hex characters.\n")
                else:
                    key = key.lower()
                    int(key, 16)
                    break

            while True:  # loop to hold requirements of Encrypt/Decrypt
                if option == "1":  # Encrypt mode
                    print("Choose the type of encryption you want:")
                    print("1. Plaintext.\n2. Picture.\n")

                elif option == "2":  # Decrypt mode
                    print("Choose the type of decryption you want:")
                    print("1. Ciphertext.\n2. Picture.\n")

                input_type = input("Enter your choice: ")
                if input_type == "1":  # Text type

                    if option == "1":  # Plaintext type if Encrypt chosen
                        text = input("\nEnter your plaintext: ")
                        plaintext = split_into_blocks(text.lower())  # splitting into 64-bit blocks
                        ciphertext = ""  # initialise empty ciphertext

                        for block in plaintext:  # iterate through all blocks and encrypt each one individually
                            cipher = tea(key, block, enc_dec="Encrypt")  # passing key and plain block in hex format
                            ciphertext += cipher  # concatenating all ciphers into final ciphertext

                        # Fill most significant with zeros that is necessary for 'from hex' method in bytes function
                        # such that multiplying length of the block with total number of blocks
                        ciphertext = ciphertext.zfill(16 * len(plaintext))
                        # Converting to bytes, decoding, then stripping extras zeros(or nulls)
                        ciphertext = bytes.fromhex(ciphertext).decode('latin-1').lstrip('\x00')
                        print("\nYour ciphertext is:", ciphertext)
                        break

                    elif option == "2":  # Ciphertext type if Decrypt chosen
                        text = input("\nEnter your ciphertext: ")
                        ciphertext = split_into_blocks(text)  # splitting into 64-bit blocks
                        plaintext = ""  # initialise empty plaintext

                        for block in ciphertext:  # iterate through all blocks and decrypt each one individually
                            plain = tea(key, block, enc_dec="Decrypt")  # passing key and cipher block in hex format
                            plaintext += plain  # concatenating all plains into final plaintext

                        # Fill most significant with zeros that is necessary for 'from hex' method in bytes function
                        # such that multiplying length of the block with total number of blocks
                        plaintext = plaintext.zfill(16 * len(ciphertext))
                        # Converting to bytes, decoding, then stripping extras zeros(or nulls)
                        plaintext = bytes.fromhex(plaintext).decode('latin-1').lstrip('\x00')
                        print("\nYour plaintext is:", plaintext)
                        break

                elif input_type == "2":  # Picture type for any mode chosen
                    picture_path = input("Enter your picture path:")
                    picture_blocks = []     # picture blocks for TEA
                    formatted_pixels = []   # formatted list for converting to hex
                    pixel_data, width, height = read_picture(picture_path)  # get picture data

                    # Converting to hex strings then splitting into blocks like blocks of text
                    for byte in pixel_data:
                        formatted_pixels.append(format(byte, '02x'))
                    for i in range(0, len(formatted_pixels), 8):
                        block = ''.join(formatted_pixels[i:i + 8])
                        picture_blocks.append(block)

                    if option == "1":  # Encryption mode
                        encrypted_picture_blocks = []  # initialise empty encrypted picture
                        for block in picture_blocks:  # iterate through all blocks and encrypt each one individually
                            encrypted_block = tea(key, block, enc_dec="Encrypt")  # passing key, block in hex format
                            encrypted_block = encrypted_block.zfill(16)     # to ensure that size as original one
                            encrypted_picture_blocks.append(encrypted_block)  # concatenating all encrypted blocks

                        pixel_data = convert_to_pixels(encrypted_picture_blocks)

                        save_picture(pixel_data, width, height, "encrypted\\")
                        print("\nEncrypted picture stored in folder called encrypted")
                        break

                    elif option == "2":  # Decryption Mode
                        decrypted_picture_blocks = []  # initialise empty encrypted picture
                        for block in picture_blocks:  # iterate through all blocks and decrypt each one individually
                            decrypted_block = tea(key, block, enc_dec="Decrypt")  # passing key, block in hex format
                            decrypted_block = decrypted_block.zfill(16)     # to ensure that size as original one
                            decrypted_picture_blocks.append(decrypted_block)  # concatenating all encrypted blocks

                        pixel_data = convert_to_pixels(decrypted_picture_blocks)

                        save_picture(pixel_data, width, height, "decrypted\\")
                        print("\nDecrypted picture stored in folder called decrypted")
                        break

                else:
                    print("Please enter a valid option.\n")

        elif option == "3":
            print("\nExit from ECB mode...\n")
            break

        else:
            print("Please enter a valid option.\n")


def tea_cbc():
    """TEA-CCB mode function"""
    print("\n================TEA Cipher Block Chaining(TEA-CBC) Mode================")

    while True:  # loop to choose encrypt/decrypt and hold all other required inputs
        print("Choose what you want:\n1. Encrypt.\n2. Decrypt.\n3. Exit.\n")

        option = input("Enter your choice: ")
        if option == "1" or option == "2":  # Encrypt/Decrypt mode
            while True:     # loop to hold the hex value of the key with the correct form
                key = input("Enter your key in hex format (128-bit, 32 hex characters): ")  # user key
                if len(key) != 32:
                    print("Key must be 32 hex characters.\n")
                else:
                    key = key.lower()
                    int(key, 16)
                    break

            while True:  # loop to hold requirements of Encrypt/Decrypt
                if option == "1":  # Encrypt mode
                    print("Choose the type of encryption you want:")
                    print("1. Plaintext.\n2. Picture.\n")

                elif option == "2":  # Decrypt mode
                    print("Choose the type of decryption you want:")
                    print("1. Ciphertext.\n2. Picture.\n")

                input_type = input("Enter your choice: ")
                if input_type == "1":  # Text type
                    if option == "1":  # Plaintext type if Encrypt chosen
                        while True:     # loop to hold the hex value of the IV with the correct form
                            iv = input("Enter the value of Initialization Vector(IV) 16 character in hex.:")
                            if len(iv) != 16:
                                print("Initialization Vector must be 16 hex characters.\n")
                            else:
                                iv = iv.lower()
                                int(iv, 16)
                                break

                        text = input("\nEnter your plaintext: ")
                        plaintext = split_into_blocks(text.lower())  # splitting into 64-bit blocks
                        ciphertext = str(iv)  # initialise ciphertext contain IV as C0
                        c_i_minus_1 = iv    # C(0) = IV

                        for block in plaintext:  # iterate through all blocks
                            c_i_minus_1 = int(c_i_minus_1, 16)
                            block = int(block, 16)
                            input_block = c_i_minus_1 ^ block   # C(i-1) XOR P(i) = Y(i)
                            input_block = hex(input_block)[2:]
                            cipher = tea(key, input_block, enc_dec="Encrypt")  # passing key, Y(i)=> C(i) = ENC(Y(i),K)
                            c_i_minus_1 = cipher    # update C(i-1) to equal C(i) for next iteration
                            ciphertext += cipher  # concatenating all ciphers into final ciphertext

                        # Fill most significant with zeros that is necessary for 'from hex' method in bytes function
                        # such that multiplying length of the block with total number of blocks
                        ciphertext = ciphertext.zfill(16 * (len(plaintext) + 1))
                        # Converting to bytes, decoding, then stripping extras zeros(or nulls)
                        ciphertext = bytes.fromhex(ciphertext).decode('latin-1').lstrip('\x00')
                        print("\nYour ciphertext is:", ciphertext)
                        break

                    elif option == "2":  # Ciphertext type if Decrypt chosen
                        text = input("\nEnter your ciphertext: ")
                        ciphertext = split_into_blocks(text)  # splitting into 64-bit blocks
                        plaintext = ""  # initialise empty plaintext
                        c_i_minus_1 = ciphertext[0]     # load IV => C(0) = IV

                        for i in range(1, len(ciphertext), 1):  # iterate through all blocks except the first
                            c_i_minus_1 = int(c_i_minus_1, 16)
                            dec = tea(key, ciphertext[i], enc_dec="Decrypt")  # passing key, cipher block=>DEC(C(i), K)
                            int_dec = int(dec, 16)
                            plain = c_i_minus_1 ^ int_dec   # P(i) = DEC(C(i), K) XOR C(i-1)
                            plain = hex(plain)[2:]
                            c_i_minus_1 = ciphertext[i]     # update C(i-1) to equal C(i) for next iteration
                            plaintext += plain  # concatenating all plains into final plaintext

                        # Fill most significant with zeros that is necessary for 'from hex' method in bytes function
                        # such that multiplying length of the block with total number of blocks
                        plaintext = plaintext.zfill(16 * (len(ciphertext)))
                        # Converting to bytes, decoding, then stripping extras zeros(or nulls)
                        plaintext = bytes.fromhex(plaintext).decode('latin-1').lstrip('\x00')
                        print("\nYour plaintext is:", plaintext)
                        break

                elif input_type == "2":  # Picture type for any mode chosen
                    picture_path = input("Enter your picture path:")
                    picture_blocks = []  # picture blocks for TEA
                    formatted_pixels = []  # formatted list for converting to hex
                    pixel_data, width, height = read_picture(picture_path)  # get picture data

                    # Converting to hex strings then splitting into blocks like blocks of text
                    for byte in pixel_data:
                        formatted_pixels.append(format(byte, '02x'))
                    for i in range(0, len(formatted_pixels), 8):
                        block = ''.join(formatted_pixels[i:i + 8])
                        picture_blocks.append(block)

                    if option == "1":  # Encryption mode
                        while True:     # loop to hold the hex value of the IV with the correct form
                            iv = input("Enter the value of Initialization Vector(IV) 16 character in hex.:")
                            if len(iv) != 16:
                                print("Initialization Vector must be 16 hex characters.\n")
                            else:
                                iv = iv.lower()
                                int(iv, 16)
                                break

                        encrypted_picture_blocks = []  # initialise ciphertext contain IV as C0
                        c_i_minus_1 = iv    # C(0) = IV

                        for block in picture_blocks:  # iterate through all blocks
                            c_i_minus_1 = int(c_i_minus_1, 16)
                            block = int(block, 16)
                            input_block = c_i_minus_1 ^ block   # C(i-1) XOR P(i) = Y(i)
                            input_block = hex(input_block)[2:]
                            cipher = tea(key, input_block, enc_dec="Encrypt")   # passing key, Y(i)=> C(i) = ENC(Y(i),K)
                            c_i_minus_1 = cipher    # update C(i-1) to equal C(i) for next iteration
                            cipher = cipher.zfill(16)   # to ensure that size as original one
                            encrypted_picture_blocks.append(cipher)  # concatenating all ciphers into final ciphertext

                        pixel_data = convert_to_pixels(encrypted_picture_blocks)

                        save_picture(pixel_data, width, height, "encrypted\\")
                        print("\nEncrypted picture stored in folder called encrypted")
                        break

                    elif option == "2":  # Decryption Mode
                        c_i_minus_1 = picture_blocks[0]
                        decrypted_picture_blocks = []  # initialise empty encrypted picture
                        for i in range(1, len(picture_blocks), 1):  # iterate through all blocks except the first
                            c_i_minus_1 = int(c_i_minus_1, 16)
                            dec = tea(key, picture_blocks[i], enc_dec="Decrypt")  # passing key and cipher block=>DEC()
                            int_dec = int(dec, 16)
                            plain = c_i_minus_1 ^ int_dec   # P(i) = DEC(C(i), K) XOR C(i-1)
                            plain = hex(plain)[2:]
                            c_i_minus_1 = picture_blocks[i]     # update C(i-1) to equal C(i) for next iteration
                            plain = plain.zfill(16)     # to ensure that size as original one
                            decrypted_picture_blocks.append(plain)  # concatenating all plains into final plaintext

                        pixel_data = convert_to_pixels(decrypted_picture_blocks)

                        save_picture(pixel_data, width, height, "decrypted\\")
                        print("\nDecrypted picture stored in folder called decrypted")
                        break

                else:
                    print("Please enter a valid option.\n")

        elif option == "3":
            print("\nExit from CBC mode...\n")
            break

        else:
            print("Please enter a valid option.\n")


def read_picture(picture_path):
    # Open the image file
    image = Image.open(picture_path)  # Replace "image_file.jpg" with the path to your image file

    # Convert the image to grayscale
    image = image.convert("L")

    # Get the pixel data
    pixel_data = list(image.getdata())

    # Get the dimensions of the image
    width, height = image.size

    return pixel_data, width, height


def convert_to_pixels(blocks):
    pixel_data = []
    # Converting to integer at max 255 which is ff in hex into pixel data list
    # that is necessary for save picture function
    for block in blocks:
        for i in range(0, len(block), 2):
            pixel = int(block[i:i + 2], 16)
            pixel_data.append(pixel)

    return pixel_data


def save_picture(data, width, height, folder):
    # Creating new encrypted/decrypted picture with same height and width of original one
    # then putting the data of it that received as parameter 'data' to write within the size
    image = Image.new("L", (width, height))
    image.putdata(data)

    # Save the picture in folder encrypted/decrypted since what is given in 'folder' parameter
    # and naming it depending on folder
    if folder == "encrypted\\":
        image.save(folder + "encrypted_picture.bmp")
    else:
        image.save(folder + "decrypted_picture.bmp")


"""=================================================MAIN================================================="""
if __name__ == '__main__':
    print("============Welcome to Tiny Encryption Algorithm(TEA)============")
    while True:  # main loop to hold user option
        print("Choose the mode of operation:\n1. Electronic Code Book Mode(ECB).")
        print("2. Cipher Block Chaining Mode(CBC).\n3. Exit.")
        mode = input("Enter your choice: ")

        if mode == "1":  # ECB MODE
            tea_ecb()
        elif mode == "2":  # CBC MODE
            tea_cbc()
        elif mode == "3":  # EXIT
            print("===============Thank you for using Tiny Encryption Algorithm(TEA)!===============")
            exit()
        else:
            print("Please enter a valid option.\n")
