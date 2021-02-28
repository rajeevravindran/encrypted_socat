from OpenSSL import crypto
import argparse
import os
parser = argparse.ArgumentParser(description='Encrypted Socat - \n\nDeveloped by Rajeev KARUVATH - CSEC 742 Computer System Security')
parser.add_argument('--listen', metavar='4443', type=int, help="Port on which socat will listen for connections")
parser.add_argument('--socat_args', metavar='socat_args', type=str, help="socat arguments")
parsed_args = parser.parse_args()
print("[*] Encrypted Socat - Developed by Rajeev KARUVATH - CSEC 742 Computer System Security")
print("[*] Generating TLS certificate")

rsa_key = crypto.PKey()
rsa_key.generate_key(crypto.TYPE_RSA, 4096)
pem_cert = crypto.X509()
pem_cert.get_subject().C = "US"
pem_cert.get_subject().ST = "New York"
pem_cert.get_subject().L = "Rochester"
pem_cert.get_subject().O = "Rochester Institute of Technology"
pem_cert.get_subject().OU = "Department of Computing Security"
pem_cert.get_subject().CN = "Rajeev KARUVATH"
pem_cert.get_subject().emailAddress = "rk3824@rit.edu"
pem_cert.gmtime_adj_notBefore(0)
pem_cert.gmtime_adj_notAfter(2*365*24*60*60)
pem_cert.set_issuer(pem_cert.get_subject())
pem_cert.set_pubkey(rsa_key)
pem_cert.sign(rsa_key, 'sha512')
with open('socat.pem', "wt") as file:
    file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, pem_cert).decode("utf-8"))
    file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, rsa_key).decode("utf-8"))
print("[*] TLS Certificate Generated")
socat_command = f"socat OPENSSL-LISTEN:{parsed_args.listen},cert=socat.pem,verify=0,fork {parsed_args.socat_args}"
print(socat_command)
os.system(socat_command)
print("[*] Closing socat")
os.remove("socat.pem")
print("[*] Deleted TLS certificate")