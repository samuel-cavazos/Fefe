from fastapi import FastAPI, Request, HTTPException
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import hashlib
import logging

# Initialize FastAPI app
app = FastAPI()

# Path to your public key
PUBLIC_KEY_PATH = "path/to/public_key.pem"

@app.post("/webhook")
async def webhook(request: Request):
    try:
        # Get the request body as bytes
        body = await request.body()

        # Extract the signature from the headers
        x_signature = request.headers.get("x-signature")
        if not x_signature:
            raise HTTPException(status_code=400, detail="Missing x-signature header")

        # Verify the signature
        if not verify_signature(body, x_signature, PUBLIC_KEY_PATH):
            raise HTTPException(status_code=400, detail="Invalid signature")

        # Parse the JSON payload
        payload = await request.json()

        # Process the event
        event_type = payload.get("event")
        if event_type == "TTS_TEXT_SUCCESS":
            handle_success(payload)
        elif event_type == "TTS_TEXT_FAILED":
            handle_failure(payload)
        else:
            logging.warning(f"Unknown event type: {event_type}")
            raise HTTPException(status_code=400, detail="Unknown event")

        return {"status": "ok"}

    except Exception as e:
        logging.error(f"Error handling webhook: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def verify_signature(data: bytes, signature: str, public_key_path: str) -> bool:
    """Verify the x-signature using the public key."""
    from cryptography.exceptions import InvalidSignature

    try:
        # Load the public key
        with open(public_key_path, "rb") as key_file:
            public_key = load_pem_public_key(key_file.read())

        # Create an MD5 hash of the data
        data_hash = hashlib.md5(data).digest()

        # Convert signature from hex to bytes
        signature_bytes = bytes.fromhex(signature)

        # Verify the signature
        public_key.verify(
            signature_bytes,
            data_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        logging.error("Invalid signature")
        return False
    except Exception as e:
        logging.error(f"Error verifying signature: {e}")
        return False


def handle_success(data):
    """Handle TTS_TEXT_SUCCESS events."""
    logging.info(f"Success event received: {data}")


def handle_failure(data):
    """Handle TTS_TEXT_FAILED events."""
    logging.info(f"Failure event received: {data}")


# Run the app
# Use `uvicorn main:app --reload` to run this app
