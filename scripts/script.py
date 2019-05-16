import os
import gnupg

os.system('rm -rf /home/haytham/gpghome')
gpg = gnupg.GPG(gnupghome='/home/haytham/gpghome')
input_data = gpg.gen_key_input(
    name_email='haytham.dahri@gmail.com',
    passphrase='toortoor')
key = gpg.gen_key(input_data)
print(f'key: {key}')

#Export keys¶
gpg = gnupg.GPG(gnupghome='/home/haytham/gpghome')
ascii_armored_public_keys = gpg.export_keys(key)
ascii_armored_private_keys = gpg.export_keys(key, True)
with open('mykeyfile.asc', 'w') as f:
    f.write(ascii_armored_public_keys)
    f.write(ascii_armored_private_keys)