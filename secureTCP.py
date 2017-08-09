#Copyright 2016 Venkatesh Gopal(vgopal3@jhu.edu), All rights reserved

from twisted.internet.protocol import Protocol, Factory
from zope.interface.declarations import implements
from twisted.internet.interfaces import ITransport, IStreamServerEndpoint
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import STRING, BOOL1, LIST, DEFAULT_VALUE, UINT4, OPTIONAL
from playground.network.common.Protocol import StackingTransport, StackingProtocolMixin, StackingFactoryMixin, MessageStorage
from Crypto.Hash import HMAC, SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from playground.crypto import X509Certificate
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from datetime import datetime
import os, random, time, math
import CertFactory
from twisted.internet import task, reactor

client_entity = ""

root = os.path.dirname(os.path.abspath(__file__))

MSS = 4096

initial_sequence = random.randrange(0,65536)
initial_sequence2 = random.randrange(0,65536)
nonce1 = ""
my_nonce = ""


class My_Message_Storage():
	sequence_number = 0
	acknowledgement_number = 0
	session_id = ""
	data_counter = 0
	send_list =[]
	receive_list = []
	data_list = []
	hold_list =[]
	current_certificate = ""
	certificate_chain =[]
	host_address = ""

storing_instance = My_Message_Storage()
	
def certificate_validate(usercertbytes,icacertbytes):

	hasher = SHA256.new()
	hasher_1 = SHA256.new()

	rootcertbytes = CertFactory.getRootCert()

	rootcert = X509Certificate.loadPEM(rootcertbytes)

	rootcert_public_key_blob = rootcert.getPublicKeyBlob()
	root_public_key = RSA.importKey(rootcert_public_key_blob)
	rootVerifier = PKCS1_v1_5.new(root_public_key)
	

	icacert = X509Certificate.loadPEM(icacertbytes)

	if(icacert.getIssuer() != rootcert.getSubject()):
		print "The certificates between root and CA don't match"
		return False

	else:
		print "############################", "\n","Checking for Certificates"		
		print "The certificates are matching"
		data = icacert.getPemEncodedCertWithoutSignatureBlob()
		hasher.update(data)
		result_1 = rootVerifier.verify(hasher,icacert.getSignatureBlob())
	
		



	usercert = X509Certificate.loadPEM(usercertbytes)

	if (result_1):
		if(usercert.getIssuer()!= icacert.getSubject()):
			print "The certificates between user and CA doesn't match"
			return False
		else:
			icacert_public_key_blob = icacert.getPublicKeyBlob()
			ica_public_key = RSA.importKey(icacert_public_key_blob)
			icaVerifier = PKCS1_v1_5.new(ica_public_key)
			
			data_1 = usercert.getPemEncodedCertWithoutSignatureBlob()
			hasher_1.update(data_1)
		
			result_2 = icaVerifier.verify(hasher_1,usercert.getSignatureBlob())
		
			
			return (result_1 and result_2)


def sign(m):

	hash_sign = SHA256.new()
	hash_sign.update(m)
	
	private_key_user = CertFactory.getPrivateKeyForAddr(storing_instance.host_address)
	
	
	private_key = RSA.importKey(private_key_user)
	rsaSigner = PKCS1_v1_5.new(private_key)
	
	return (rsaSigner.sign(hash_sign))
		
def signature_verify(m,message,user_cert_bytes):
	v = MySrpHeader()
	v = message
	v.signature = ""
	hash_verify = SHA256.new()
	hash_verify.update(v.__serialize__())

	usercert = X509Certificate.loadPEM(user_cert_bytes)
	user_public_key_blob = usercert.getPublicKeyBlob()
	user_public_key = RSA.importKey(user_public_key_blob)
	rsaVerifier = PKCS1_v1_5.new(user_public_key)

	verify = rsaVerifier.verify(hash_verify,m)
	return verify
	

class MySrpHeader(MessageDefinition):
	PLAYGROUND_IDENTIFIER = "RIP.RIPMessageID"
	MESSAGE_VERSION = "1.0"
	
	BODY = [ ("sequence_number", UINT4),
		 ("acknowledgement_number", UINT4,OPTIONAL),
		 ("signature", STRING, DEFAULT_VALUE("")),
		 ("certificate", LIST(STRING), OPTIONAL),
		 ("sessionID", STRING),
		 ("acknowledgement_flag",BOOL1,DEFAULT_VALUE(False)),
		 ("close_flag", BOOL1,DEFAULT_VALUE(False)),
		 ("sequence_number_notification_flag", BOOL1,DEFAULT_VALUE(False)),
		 ("reset_flag", BOOL1,DEFAULT_VALUE(False)),
		 ("data", STRING,DEFAULT_VALUE("")),
		 ("OPTIONS",LIST(STRING),OPTIONAL)
	       ]	

	
	
class MySrpTransport(StackingTransport):
	
	def __init__(self, lowerTransport):
		StackingTransport.__init__(self, lowerTransport)

		
		
	def write(self, data):
		if (len(data) > MSS):
			print "Length of data is", len(data), "This needs to be segmented"
			self.writesegmenteddata(data)
			return
			
		
		else:		
			message_from_application = MySrpHeader()
			message_from_application.sequence_number = storing_instance.sequence_number
			storing_instance.sequence_number = storing_instance.sequence_number + len(data)
			message_from_application.acknowledgement_number = storing_instance.acknowledgement_number
			message_from_application.data = data
			message_from_application.sessionID = storing_instance.session_id
			message_from_application.signature = ""
			send_bytes = message_from_application.__serialize__()
			message_from_application.signature = sign(send_bytes)
			print "Sending data packets:", " Sequence number: ", message_from_application.sequence_number, "Acknowledgement number: ", message_from_application.acknowledgement_number, " to Peer", self.lowerTransport().getPeer()
			tup1 = [time.time(),message_from_application.sequence_number, message_from_application,0]
			storing_instance.send_list.append(tup1)
		
			self.lowerTransport().write(message_from_application.__serialize__())
			
			
		task.deferLater(reactor,8,self.retransmission)
		
			

	def retransmission(self):
		length = len(storing_instance.send_list)
		if length == 0:
			print "Checking for re-transmisssions, Received ACK for all segments sent till now"

		else:
			print "Sending all segments for which ACK has not been received"
			for i in range(0,length):
				if(int(time.time() - storing_instance.send_list[i][0]) > 8):
					if(storing_instance.send_list[i][3] < 10):

						print "Retransmitting segment with sequence number :", storing_instance.send_list[i][1] 
						self.lowerTransport().write(storing_instance.send_list[i][2].__serialize__())
						storing_instance.send_list[i][3]+=1
					else:
						print "Not retransmitting since these segments have already been re-transmitted 10 times"
			task.deferLater(reactor,8,self.retransmission)
					
		
						
	def writesegmenteddata(self,data):
		
		segmented_data = MySrpHeader()
		a = float(len(data))
		b = a/MSS
		c = math.ceil(b)
		number_of_segments = int(c)
		
		print "The number of segmnets",number_of_segments
		for n in range(0,number_of_segments):
			startrange = n*MSS
			stoprange = ((n+1)*MSS) 
			
			data_to_send = data[startrange:stoprange]
			
			message_from_application = MySrpHeader()
			message_from_application.sequence_number = storing_instance.sequence_number
			storing_instance.sequence_number = storing_instance.sequence_number + len(data_to_send) 
			message_from_application.acknowledgement_number = storing_instance.acknowledgement_number
			message_from_application.data = data_to_send
			message_from_application.sessionID = storing_instance.session_id
			message_from_application.signature = ""
			send_bytes = message_from_application.__serialize__()
			message_from_application.signature = sign(send_bytes)
			print "Sending data packets:", " Sequence number: ", message_from_application.sequence_number, "Acknowledgement number: ", message_from_application.acknowledgement_number, " to Peer", self.lowerTransport().getPeer()
			tup1 = [time.time(),message_from_application.sequence_number, message_from_application,0]
			storing_instance.send_list.append(tup1)
		
			self.lowerTransport().write(message_from_application.__serialize__())
		
			
		task.deferLater(reactor,8,self.retransmission)
		
			


			
			
	
	def loseConnection(self):
		
		if client_entity == "Client":
			close_packet = MySrpHeader()
			close_packet.close_flag = True
			close_packet.signature = ""
			close_packet.sequence_number = storing_instance.sequence_number
			close_packet.acknowledgement_number = storing_instance.acknowledgement_number + 1
			close_packet.sessionID = storing_instance.session_id
			
			send_bytes = close_packet.__serialize__()
			close_packet.signature = sign(send_bytes)
			
			print "Sending request to close to Peer:"
			
			self.lowerTransport().write(close_packet.__serialize__())
	

class MySrpProtocol(StackingProtocolMixin, Protocol):
	def __init__(self):
        	self.buffer = ""
        	self.storage = MessageStorage()
	
	def connectionMade(self):
		
		
		syn_packet = MySrpHeader()
		syn_packet.sequence_number = 0
		syn_packet.acknowledgement_number = 0
		if(syn_packet.sequence_number == 0 and syn_packet.acknowledgement_number == 0):
			if self.factory.state =="Connect":
				
				syn_packet.sequence_number = initial_sequence
				syn_packet.acknowledgement_number = 0
				syn_packet.sequence_number_notification_flag = True
				syn_packet.sessionID = ""
				storing_instance.certificate_chain = CertFactory.getCertsForAddr(self.transport.getHost().host)
				
				storing_instance.host_address = str(self.transport.getHost().host)
				
				usercertbytes = storing_instance.certificate_chain[0]
				icacertbytes = storing_instance.certificate_chain[1]
				nonce = os.urandom(8).encode("hex")
				global my_nonce
				my_nonce = nonce
				syn_packet.certificate = [nonce,usercertbytes,icacertbytes]
				syn_packet.signature = ""
				send_bytes = syn_packet.__serialize__()
				syn_packet.signature = sign(send_bytes)
				
				print datetime.now()," Sending a snn", " Seq Number: ", syn_packet.sequence_number,"Ack Number: ", syn_packet.acknowledgement_number, " to Peer", self.transport.getPeer()

				self.transport.write(syn_packet.__serialize__())
				
	
				

			
	def dataReceived(self,data):
		
		self.buffer += data
		self.storage.update(data)
		

		for msg in self.storage.iterateMessages():
			
			
			try:
				message = msg
				
				
			except Exception, e:
				print "We had a deserilization error", e
				return
			
			
			if(message.sequence_number_notification_flag and self.factory.state=="Listen" ):
				if self.factory.state =="Listen":
				
					print datetime.now(), " Received snn"," Seq Number: ",message.sequence_number," Ack Number: ", message.acknowledgement_number, " from Peer", self.transport.getPeer()
					
					syn_verify_certificate = certificate_validate(message.certificate[1],message.certificate[2])
						
					if syn_verify_certificate:
						if signature_verify(message.signature,message,message.certificate[1]):
							print "SIGNATURE VERIFIED IN SYN PACKET"
							
							a = os.urandom(8).encode("hex")
							global nonce1
							nonce1 = a
							b = int(message.certificate[0],16)
							b = b + 1
							b = hex(b)
							b = b.lstrip('0x').rstrip('L')
							
							storing_instance.current_certificate = message.certificate[1]
							
							#storing_instance.host_address = get_address_from_playground_output(str(self.transport.getHost()))
							storing_instance.host_address = str(self.transport.getHost().host)
							print "The playground address is: ", storing_instance.host_address
							storing_instance.session_id = a + message.certificate[0]
							syn_ack_packet = MySrpHeader()
							syn_ack_packet.sessionID = ""
							syn_ack_packet.sequence_number = initial_sequence2
							syn_ack_packet.acknowledgement_number = message.sequence_number + 1
							syn_ack_packet.sequence_number_notification_flag = True
							syn_ack_packet.acknowledgement_flag = True
							
							storing_instance.certificate_chain = CertFactory.getCertsForAddr(self.transport.getHost().host)
							#storing_instance.certificate_chain = CertFactory.getCertsForAddr(get_address_from_playground_output(str(self.transport.getHost())))
						

							syn_ack_packet.certificate = [a,b,storing_instance.certificate_chain[0],storing_instance.certificate_chain[1]]
							syn_ack_packet.signature = ""
							send_bytes = syn_ack_packet.__serialize__()
							syn_ack_packet.signature = sign(send_bytes)
							print datetime.now()," Sending Snn ack"," Seq Number: ", syn_ack_packet.sequence_number,"Ack Number: ", syn_ack_packet.acknowledgement_number, ":to Peer" , self.transport.getPeer()

							self.transport.write(syn_ack_packet.__serialize__())
						else:
							print "Signature not matching in SNN: Authentication failure, Ignoring packets"
					
					else :

						print "Certificates not matching in SNN, Ignoring packets"

							

			elif(message.sequence_number_notification_flag and message.acknowledgement_flag):
				if self.factory.state =="Connect":

					print datetime.now()," Client has Received Snn ACK"," Seq Number: ",message.sequence_number," Ack Number: ", message.acknowledgement_number, "from Peer", self.transport.getPeer()
					
					syn_ack_packet_verify_certificate = certificate_validate(message.certificate[2],message.certificate[3])
				
					if syn_ack_packet_verify_certificate:

						if signature_verify(message.signature,message,message.certificate[2]):
							print "SIGNATURE VERIFIED IN SYN-ACK"
							
							c = int(message.certificate[0],16) + 1
							c = hex(c)
							c = c.lstrip('0x').rstrip('L')
						
							global client_entity
							client_entity = self.factory.name
						
							storing_instance.current_certificate = message.certificate[2]
							storing_instance.session_id = my_nonce + message.certificate[0]
							ack_packet = MySrpHeader()
							ack_packet.sessionID = storing_instance.session_id
							ack_packet.sequence_number = message.acknowledgement_number
							ack_packet.acknowledgement_number = message.sequence_number + 1
							ack_packet.sequence_number_notification_flag = False
							ack_packet.acknowledgement_flag = True
						
						
							storing_instance.sequence_number = message.acknowledgement_number + 1
							storing_instance.acknowledgement_number = message.sequence_number + 1
							ack_packet.certificate = [c]
							print "Sending nonce in ACK", ack_packet.certificate[0]
					
							ack_packet.signature = ""
							bytes = ack_packet.__serialize__()
							ack_packet.signature = sign(bytes)
							print datetime.now()," Sending Ack"," Seq Number: ", ack_packet.sequence_number,"Ack Number: ", ack_packet.acknowledgement_number, " to Peer", self.transport.getPeer()
							self.transport.write(ack_packet.__serialize__())
							self.factory.state="receive"
				
						else:
							print "Signature not matching in SNN-ACK: Authentication failure, Ignoring packets"
					else:
						print "Certificates not matching in SNN-ACK, Ignoring packets"	
					

			elif(not message.sequence_number_notification_flag and message.acknowledgement_flag):
				
				if self.factory.state == "Listen":
					print datetime.now(), " Received ACK, Connection Established"," Seq Number: ",message.sequence_number," Ack Number:",message.acknowledgement_number, " from Peer", self.transport.getPeer()

					if signature_verify(message.signature,message,storing_instance.current_certificate):
						print "SIGNATURE VERIFIED IN ACK"
						
						storing_instance.sequence_number = message.acknowledgement_number
						storing_instance.acknowledgement_number = message.sequence_number + 1
						self.factory.state="receive"

					else:
						print "Signature not matching in ACK: Authentication failure, Ignoring packets"

				elif (self.factory.state == "established" and (not message.close_flag)):
					if signature_verify(message.signature,message,storing_instance.current_certificate):
						for i in range(0,len(storing_instance.send_list)):
							if (message.acknowledgement_number == (storing_instance.send_list[i][1] + len(storing_instance.send_list[i][2].data))):

								storing_instance.send_list.remove(storing_instance.send_list[i])
								
								print "Received ack from peer ", self.transport.getPeer(), "He is expecting sequence number", message.acknowledgement_number 	
								break
								
				
						
			if (self.factory.state=="receive"):
			
				higherTransport = MySrpTransport(self.transport)
				self.makeHigherConnection(higherTransport)
				self.factory.state = "established"	
				print "##############\nSession Established with Session ID :", storing_instance.session_id, "\n##############"
		
			if (self.factory.state == "established" and message.data!=""):
				
				if signature_verify(message.signature,message,storing_instance.current_certificate):
					print "SIGNATURE VERIFIED"
					
					length = 0
					if (len(storing_instance.receive_list) == 0):
						tup2 = (message.sequence_number,message)
						storing_instance.receive_list.append(tup2)
						length = len(storing_instance.receive_list)
						print "I have received", length, "segments till now"
	
						print "This is the first segment I have received"
						ack_for_data = MySrpHeader()
						ack_for_data.sequence_number = 100
						ack_for_data.acknowledgement_number = message.sequence_number + len(message.data) 
						ack_for_data.sessionID = storing_instance.session_id
						ack_for_data.signature = ""
						ack_for_data.acknowledgement_flag = True
						send_bytes = ack_for_data.__serialize__()
						ack_for_data.signature = sign(send_bytes)
						print " Sending data to application & also sending ACK for this data"
						self.transport.write(ack_for_data.__serialize__())
						self.higherProtocol() and self.higherProtocol().dataReceived(message.data)
					else:	
						if(duplicate_check(message.sequence_number)):
							print "Received duplicate packet, dropping it"
				
						elif(message.sequence_number == storing_instance.receive_list[length -1][0] + len(storing_instance.receive_list[length-1][1].data)):
							print " Current segment received is in order"
							tup2 = (message.sequence_number,message)
							storing_instance.receive_list.append(tup2)
							length = len(storing_instance.receive_list)
							print "I have received", length, "segments till now"
							
							ack_for_data = MySrpHeader()
							ack_for_data.sequence_number = 100
							ack_for_data.acknowledgement_number = message.sequence_number + len(message.data)
							ack_for_data.sessionID = storing_instance.session_id
							ack_for_data.signature = ""
							ack_for_data.acknowledgement_flag = True
							send_bytes = ack_for_data.__serialize__()
							ack_for_data.signature = sign(send_bytes)
							print " Sending data to application & also sending ACK for this data"
							self.transport.write(ack_for_data.__serialize__())
							self.higherProtocol() and self.higherProtocol().dataReceived(message.data)
	
						else:
							print "Segments out of order, Not going to send an acknowledgement"
							
			if (message.close_flag):


				if (message.acknowledgement_flag):
					print "Reached here"
					if signature_verify(message.signature,message,storing_instance.current_certificate):			
						print "Received ack from Server for closure"
						self.higherProtocol().connectionLost(self.transport)
							

					
	
				else:
					
					if signature_verify(message.signature,message,storing_instance.current_certificate):
						print "Received request from client to finish", " from Peer" , self.transport.getPeer()
						climax_packet = MySrpHeader()
						climax_packet.acknowledgement_flag = True
						climax_packet.close_flag = True
						climax_packet.sequence_number = storing_instance.acknowledgement_number
						climax_packet.acknowledgement_number = storing_instance.sequence_number + 1
						climax_packet.sessionID = storing_instance.session_id	
						climax_packet.signature = ""
						climax_packet.certificate = [storing_instance.certificate_chain[0],storing_instance.certificate_chain[1]]
						send_bytes = climax_packet.__serialize__()
						climax_packet.signature = sign(send_bytes)
						print "Sending ack for closure"
						print "#######################"
						self.transport.write(climax_packet.__serialize__())
						self.higherProtocol().connectionLost(self.transport)

def get_address_from_playground_output(call):
	output = ""
	output = call
	c = ""
	for i in range(0,len(output)):
		if(output[i]==":"):
			c = output[0:i]
			
			return c
			break


	
						
#Function to check duplicate segments				
def duplicate_check(seq):
	for i in range(0,len(storing_instance.receive_list)):
		if(seq ==  storing_instance.receive_list[i][0]):
			return True
		


class MySrpFactory(StackingFactoryMixin, Factory):
	protocol = MySrpProtocol
	state = "Connect"
	name = "Client"
	

class MySrpFactory1(StackingFactoryMixin, Factory):
	protocol = MySrpProtocol
	state = "Listen"
	name = "Server"


ConnectFactory = MySrpFactory
ListenFactory = MySrpFactory1
