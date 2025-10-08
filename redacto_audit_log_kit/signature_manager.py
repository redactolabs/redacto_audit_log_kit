from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import json
import os

class SignatureManager:
    def __init__(self, key_path=None):
        """Initialize with existing keys or generate new ones"""
        self.private_key = None
        self.public_key = None
        
        if key_path and os.path.exists(f"{key_path}/private_key.pem"):
            self._load_keys(key_path)
        else:
            self._generate_keys(key_path)
    
    def _generate_keys(self, key_path=None):
        """Generate new RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        if key_path:
            os.makedirs(key_path, exist_ok=True)
            # Save private key
            with open(f"{key_path}/private_key.pem", "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            # Save public key
            with open(f"{key_path}/public_key.pem", "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
    
    def _load_keys(self, key_path):
        """Load existing keys from files"""
        with open(f"{key_path}/private_key.pem", "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        with open(f"{key_path}/public_key.pem", "rb") as f:
            self.public_key = serialization.load_pem_public_key(
                f.read()
            )
    
    def _canonicalize(self, event_dict):
        """Create a canonical representation of the event data"""
        # Sort keys to ensure consistent ordering
        return json.dumps(event_dict, sort_keys=True).encode()
    
    def sign_event(self, event_dict):
        """Sign an event"""
        # Create a copy to avoid modifying the original
        event_to_sign = event_dict.copy()
        
        # Create canonical representation
        data = self._canonicalize(event_to_sign)
        
        # Sign the data
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Return signed event
        event_to_sign["_signature"] = signature.hex()
        return event_to_sign
    
    def verify_event(self, signed_event):
        """Verify the signature of an event"""
        # Extract signature
        signature = bytes.fromhex(signed_event["_signature"])
        
        # Create a copy without the signature for verification
        event_to_verify = signed_event.copy()
        event_to_verify.pop("_signature")
        
        # Create canonical representation
        data = self._canonicalize(event_to_verify)
        
        try:
            # Verify signature
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False