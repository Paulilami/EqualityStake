// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IMultisig {
   function addSignature(uint256 _transactionId, bytes memory _signature) external;
   function checkSignatures(uint256 _transactionId) external view returns (bool);
   function verifyProof(bytes memory _proof, address _publicKey) external returns (bool);
}

contract MultisigWallet is IMultisig {
   mapping(uint256 => Transaction) public transactions;
   mapping(uint256 => mapping(address => bool)) public signatures;
   mapping(address => bool) public authorizedKeys;

   uint256 public nonce;
   uint256 public threshold;

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

   constructor(uint256 _threshold, address[] memory _authorizedKeys) {
       require(_threshold > 0 && _threshold <= _authorizedKeys.length, "Invalid threshold");
       threshold = _threshold;

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

   function addSignature(uint256 _transactionId, bytes memory _signature) external override onlyAuthorized {
       require(!signatures[_transactionId][msg.sender], "Already signed");
       require(!transactions[_transactionId].executed, "Transaction already executed");

       bytes32 messageHash = getTransactionHash(_transactionId);
       address signer = recoverSigner(messageHash, _signature);
       require(authorizedKeys[signer], "Unauthorized signer");

       signatures[_transactionId][signer] = true;
       transactions[_transactionId].numSignatures++;

       emit SignatureAdded(_transactionId, signer);
   }

   function checkSignatures(uint256 _transactionId) public view override returns (bool) {
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

   function verifyProof(bytes memory _proof, address _publicKey) external override returns (bool) {
       // Implementation for verifying zk-SNARK proofs
       // ...

       if (validProof) {
           authorizedKeys[_publicKey] = true;
       }

       return validProof;
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
