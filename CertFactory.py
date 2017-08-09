import os
root = os.path.dirname(os.path.abspath(__file__))

def getCertsForAddr(addr):
	chain = []

	# Enter the location of the user's certificate as per the user's system	
	with open(root+ "/sign/user1_signed.cert") as fo:
		chain.append(fo.read())

	# Enter the location of the CA certificate as per the location of the system
	with open(root + "/sign/gvenky_signed.cert") as fi:
		chain.append(fi.read())
	
	return chain
		


def getPrivateKeyForAddr(addr):
	# Enter the location of the Private key as per the location of the system
	with open(root + "/sign/user1_private")as fp:
		private_key_user = fp.read()

	return private_key_user

def getRootCert():
	# Enter the location of the Root certificate
	with open(root + "/sign/20164_signed.cert") as f:
		rootcertbytes = f.read()
	
	return rootcertbytes
