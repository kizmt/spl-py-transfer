from bip_utils import Bip39SeedGenerator, Bip32, Bip44, Bip44Coins
from solana.account import Account
from solana.rpc.api import Client
from solana.transaction import Transaction, TransactionInstruction
from solana.system_program import TransferParams, transfer
from solana.publickey import PublicKey

def generate_keypair_from_mnemonic(mnemonic):
    """Generate a keypair (public and private key) from a given mnemonic phrase.

    Args:
        mnemonic (str): The mnemonic phrase.

    Returns:
        tuple: A tuple containing the private key and the public key bytes.
    """
    # Generate a seed from the mnemonic
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    # Derive the root key from the seed
    root_key = Bip32.FromSeed(seed_bytes)
    # Derive the Solana account key path
    solana_acc_path = Bip44.FromCoin(Bip44Coins.SOLANA).DeriveAccount(root_key)
    # Get the private key bytes
    private_key = solana_acc_path.PrivateKey().Raw().ToBytes()
    # Get the public key bytes
    public_key = solana_acc_path.PublicKey().RawCompressed().ToBytes()
    return private_key, public_key

def transfer_spl_token(sender_private_key, recipient_public_key, amount):
    """Transfer SPL tokens from one account to another.

    Args:
        sender_private_key (bytes): The sender's private key bytes.
        recipient_public_key (bytes): The recipient's public key bytes.
        amount (int): The amount of SPL tokens to transfer.

    Returns:
        str: The transaction signature.
    """
    # Create an account object for the sender using the private key
    sender_acc = Account(sender_private_key)
    # Convert recipient public key bytes to PublicKey object
    recipient_acc = PublicKey(recipient_public_key)
    # Create a Solana RPC client
    client = Client("https://api.devnet.solana.com")

    # Create transfer instruction
    transfer_instruction = transfer(
        TransferParams(
            from_pubkey=sender_acc.public_key(),
            to_pubkey=recipient_acc,
            lamports=amount
        )
    )

    # Create a transaction
    transaction = Transaction()
    transaction.add(transfer_instruction)

    # Sign the transaction
    transaction.sign(sender_acc)

    try:
        # Send the transaction and get the signature
        response = client.send_transaction(transaction, sender_acc)
        tx_sig = response["result"]
    except Exception as e:
        return f"An error occurred: {str(e)}"

    return tx_sig

if __name__ == "__main__":
    # This part of the code will only execute if the script is run directly
    # Replace "your twelve word mnemonic here" with your actual mnemonic
    mnemonic = "your twelve word mnemonic here"
    # Generate keypair from the mnemonic
    sender_private_key, sender_public_key = generate_keypair_from_mnemonic(mnemonic)
    # Replace "recipient_public_key_here" with the recipient's public key (hex format)
    recipient_public_key_hex = "recipient_public_key_here"
    recipient_public_key = bytes.fromhex(recipient_public_key_hex)
    # Define the amount of SPL token to transfer (in lamports)
    amount = 1000000  # Adjust as needed
    # Perform the token transfer
    transaction_signature = transfer_spl_token(sender_private_key, recipient_public_key, amount)
    # Print the transaction signature
    print("Transaction Signature:", transaction_signature)
