import base64
import hashlib
import json
import time
from typing import Dict, Any

import didery.crypto.ed25519 as ed25519
import didery.did as did
import didery.schema as schema

class Cord:
    @staticmethod
    def create_verifiable_document(content: Dict[str, Any], issuer_did: did.DID, schema_uri: str) -> Dict[str, Any]:
       
        function createVerifiableDocument(content, issuerDid, schemaUri) {
  const serializedCred = Cord.Utils.Crypto.encodeObjectAsStr(content);
  const credHash = Cord.Utils.Crypto.hashStr(serializedCred);

  const statementEntry = Cord.Statement.buildFromProperties(
    credHash,
    space.uri,
    issuerDid.uri,
    schemaUri
  );

  return Cord.Statement.dispatchRegisterToChain(
    statementEntry,
    issuerDid.uri,
    authorIdentity,
    space.authorization,
    async ({ data }) => {
      const receipt = await Cord.Utils.Chain.waitForTransactionReceipt(data);
      console.log(Statement registered on chain with receipt: ${receipt});
    }
  );
}
       
        issuance_date = int(time.time())
        content['issuanceDate'] = issuance_date
        serialized_cred = json.dumps(content, sort_keys=True)
        cred_hash = hashlib.sha256(serialized_cred.encode()).hexdigest()

        statement_entry = Cord.Statement.build_from_properties(
            cred_hash,
            schema_uri,
            issuer_did.uri,
            schema_uri
        )

        return {
            'id': cred_hash,
            'type': 'VerifiableCredential',
            'issuer': issuer_did.uri,
            'issuanceDate': issuance_date,
            'credentialSubject': content,
            'proof': statement_entry.to_dict()
        }

    class Statement:
        @staticmethod
        def build_from_properties(cred_hash: str, schema_uri: str, issuer_did: str, schema_uri: str) -> 'Cord.Statement':
            """
            Build a statement from the given properties.

            :param cred_hash: The hash of the credential.
            :param schema_uri: The URI of the schema.
            :param issuer_did: The DID of the issuer.
            :param schema_uri: The URI of the schema.
            :return: The statement.
            """
            return Cord.Statement(
                cred_hash,
                schema_uri,
                issuer_did,
                schema_uri
            )

        def __init__(self, cred_hash: str, schema_uri: str, issuer_did: str, schema_uri: str):
            self.cred_hash = cred_hash
            self.schema_uri = schema_uri
            self.issuer_did = issuer_did
            self.schema_uri = schema_uri

        def to_dict(self) -> Dict[str, Any]:
            """
            Convert the statement to a dictionary.

            :return: The dictionary representation of the statement.
            """
            return {
                'type': 'Statement',
                'credentialHash': self.cred_hash,
                'schemaUri': self.schema_uri,
                'issuerDid': self.issuer_did,
                'schemaUri': self.schema_uri
            }