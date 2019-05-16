import os
import fs
from fs import open_fs
import gnupg

gpg = gnupg.GPG(gnupghome="/home/haytham/.gnupg")
home_fs = open_fs(".")
if os.path.exists("signatures/"):
        print("Signatures directory already created")
else:
        home_fs.makedir(u"signatures")
        print("Created signatures directory")

# Store all directory file in the files_dir array
files_dir = []

files = [f for f in os.listdir(".") if os.path.isfile(f)]
for f in files:
    files_dir.append(f)

# Display stored file in files_dir array
for file in files_dir:
    print(f'File: {file}')

# Generate signature for each file using the passphrase
# When finished, all the signatures will be moved to the signatures/ folder.
for x in files_dir:
    with open(x, "rb") as f:
        stream = gpg.sign_file(f,passphrase="toortoor",detach = True, output=files_dir[files_dir.index(x)]+".sig")
        os.rename(files_dir[files_dir.index(x)]+".sig", "signatures/"+files_dir[files_dir.index(x)]+".sig")
        print(x+" ", stream.status)