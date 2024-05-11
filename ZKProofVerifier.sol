// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@ethereum/circomlib/contracts/circuits/EdDSMPlonK.sol";
import "@ethereum/circomlib/contracts/circuits/EdDSMPlonKVerifier.sol";

contract ZKProofVerifier is EdDSMPlonKVerifier {
   mapping(address => uint256) public keyNonces;

   function verifyProof(bytes memory _proof, address _publicKey) public returns (bool) {
       uint256 nonce = keyNonces[_publicKey];
       keyNonces[_publicKey]++;

       bytes memory input = abi.encodePacked(_publicKey, nonce);
       uint256[] memory inputValues = convertBytesToUint256Array(input);

       bool validProof = EdDSMPlonKVerifier.verifyProof(
           _proof,
           inputValues,
           [
               1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
           ]
       );

       return validProof;
   }

   function convertBytesToUint256Array(bytes memory _bytes) internal pure returns (uint256[] memory) {
       uint256[] memory result = new uint256[](_bytes.length / 32);
       uint256 i = 0;
       for (i = 0; i < _bytes.length / 32; i++) {
           result[i] = bytesToUint256(_bytes, i * 32);
       }
       return result;
   }

   function bytesToUint256(bytes memory _bytes, uint256 _start) internal pure returns (uint256) {
       require(_bytes.length >= _start + 32, "Insufficient bytes");
       uint256 result = 0;
       for (uint256 i = _start; i < _start + 32; i++) {
           result = result * 256 + uint256(uint8(_bytes[i]));
       }
       return result;
   }
}

contract PrivateMultisigWallet {
   mapping(uint256 => Transaction) public transactions;
   mapping(uint256 => mapping(address => bool)) public signatures;
   mapping(address => bool) public authorizedKeys;

   uint256 public nonce;
   uint256 public threshold;

   ZKProofVerifier public zkVerifier;

   struct Transaction {
       address to;
       uint256 value;
       bytes data;
       bool executed;
       uint256 numSignatures;
   }

   event TransactionProposed(uint256 indexed transactionId, address indexed proposer);
   event TransactionExecuted(uint256 indexed transactionId);
   event SignatureAdded(uint256 indexed transactionId, address indexed signer);

   modifier onlyAuthorized() {
       require(authorizedKeys[msg.sender], "Unauthorized");
       _;
   }

   constructor(uint256 _threshold, address[] memory _authorizedKeys, ZKProofVerifier _zkVerifier) {
       require(_threshold > 0 && _threshold <= _authorizedKeys.length, "Invalid threshold");
       threshold = _threshold;
       zkVerifier = _zkVerifier;

       for (uint256 i = 0; i < _authorizedKeys.length; i++) {
           authorizedKeys[_authorizedKeys[i]] = true;
       }
   }

   function proposeTransaction(address _to, uint256 _value, bytes memory _data) external onlyAuthorized returns (uint256) {
       uint256 transactionId = nonce++;
       transactions[transactionId] = Transaction({
           to: _to,
           value: _value,
           data: _data,
           executed: false,
           numSignatures: 0
       });

       signatures[transactionId][msg.sender] = true;
       transactions[transactionId].numSignatures++;

       emit TransactionProposed(transactionId, msg.sender);

       return transactionId;
   }

   function addSignature(uint256 _transactionId, bytes memory _signature) external onlyAuthorized {
       require(!signatures[_transactionId][msg.sender], "Already signed");
       require(!transactions[_transactionId].executed, "Transaction already executed");

       bytes32 messageHash = getTransactionHash(_transactionId);
       address signer = recoverSigner(messageHash, _signature);
       require(authorizedKeys[signer], "Unauthorized signer");

       signatures[_transactionId][signer] = true;
       transactions[_transactionId].numSignatures++;

       emit SignatureAdded(_transactionId, signer);
   }

   function checkSignatures(uint256 _transactionId) public view returns (bool) {
       return transactions[_transactionId].numSignatures >= threshold;
   }

   function executeTransaction(uint256 _transactionId) external onlyAuthorized {
       require(checkSignatures(_transactionId), "Not enough signatures");
       require(!transactions[_transactionId].executed, "Transaction already executed");

       Transaction storage transaction = transactions[_transactionId];
       transaction.executed = true;

       (bool success, ) = transaction.to.call{value: transaction.value}(transaction.data);
       require(success, "Transaction execution failed");

       emit TransactionExecuted(_transactionId);
   }

   function authorizeKey(bytes memory _proof, address _publicKey) external {
       require(zkVerifier.verifyProof(_proof, _publicKey), "Invalid proof");
       authorizedKeys[_publicKey] = true;
   }

   function getTransactionHash(uint256 _transactionId) public view returns (bytes32) {
       Transaction storage transaction = transactions[_transactionId];
       return keccak256(abi.encodePacked(transaction.to, transaction.value, transaction.data, nonce));
   }

   function recoverSigner(bytes32 _messageHash, bytes memory _signature) internal pure returns (address) {
       bytes32 r;
       bytes32 s;
       uint8 v;

       if (_signature.length != 65) {
           return address(0);
       }

       assembly {
           r := mload(add(_signature, 32))
           s := mload(add(_signature, 64))
           v := byte(0, mload(add(_signature, 96)))
       }

       if (v < 27) {
           v += 27;
       }

       if (v != 27 && v != 28) {
           return address(0);
       }

       return ecrecover(_messageHash, v, r, s);
   }
}
