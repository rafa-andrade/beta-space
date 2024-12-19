# #!/usr/bin/env python3
# from http import server # Python 3

# class MyHTTPRequestHandler(server.SimpleHTTPRequestHandler):
#         def end_headers(self):
#                 self.send_my_headers()
#                 server.SimpleHTTPRequestHandler.end_headers(self)

#         def send_my_headers(self):
#                 self.send_header("Access-Control-Allow-Origin", "*")
#                 self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
#                 self.send_header("Cross-Origin-Opener-Policy", "same-origin")

# if __name__ == '__main__':
#         server.test(HandlerClass=MyHTTPRequestHandler)

import http.server
import ssl
import datetime
import tempfile
import os
import argparse
import signal
import threading
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509.oid import NameOID


class MyRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")

        self.send_header(
            "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
        )
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()


# Generate a self-signed certificate
def get_cert_and_key():
    # Generate a self-signed certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    )
    builder = builder.issuer_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    )
    builder = builder.not_valid_before(
        datetime.datetime.now() - datetime.timedelta(days=1)
    )
    builder = builder.not_valid_after(
        datetime.datetime.now() + datetime.timedelta(days=365)
    )
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    certificate = builder.sign(
        private_key=private_key, algorithm=SHA256(), backend=default_backend()
    )

    # Create a temporary directory to store the certificate and key
    temp_dir = tempfile.mkdtemp()
    print(f"generating temp certs in {temp_dir}")
    cert_path = os.path.join(temp_dir, "server.crt")
    key_path = os.path.join(temp_dir, "server.key")

    # Write the certificate and key to files in the temporary directory
    with open(cert_path, "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return cert_path, key_path


# Command-line argument parsing
parser = argparse.ArgumentParser(description="Start a simple HTTP(S) server.")
parser.add_argument(
    "-u",
    "--unsecure",
    action="store_true",
    help="Use HTTP instead of HTTPS (default: HTTPS)",
)

args = parser.parse_args()

# Set port and server configuration based on arguments
if args.unsecure:
    server_address = ("localhost", 8080)
    httpd = http.server.HTTPServer(server_address, MyRequestHandler)
    print(f"Serving on http://{server_address[0]}:{server_address[1]}/")
else:
    cert_path, key_path = get_cert_and_key()
    server_address = ("localhost", 4443)
    httpd = http.server.HTTPServer(server_address, MyRequestHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"Serving on https://{server_address[0]}:{server_address[1]}/")


def interrupt_handler(sig, frame):
    print("\nKeyboard interrupt received. Shutting down the server...")
    httpd.shutdown()
    httpd.server_close()
    print("Server stopped.")


# Set the interrupt handler for SIGINT (Ctrl-C)
signal.signal(signal.SIGINT, interrupt_handler)

server_thread = threading.Thread(target=httpd.serve_forever)
print(f"Starting server (on thread {server_thread.name}). Press Ctrl-C to stop.")
# Exit the server thread when the main thread terminates
server_thread.daemon = True
server_thread.start()
server_thread.join()