// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@ethereum/circomlib/contracts/circuits/EdDSMPlonK.sol";
import "@ethereum/circomlib/contracts/circuits/EdDSMPlonKVerifier.sol";

contract AccessControl is EdDSMPlonKVerifier {
   mapping(address => bool) public authorizedKeys;
   mapping(address => uint256) public keyNonces;

   event AuthorizedKeyAdded(address indexed key);
   event AuthorizedKeyRemoved(address indexed key);

   modifier onlyAuthorized() {
       require(authorizedKeys[msg.sender], "Unauthorized access");
       _;
   }

   function addAuthorizedKey(address _key) external onlyAuthorized {
       authorizedKeys[_key] = true;
       emit AuthorizedKeyAdded(_key);
   }

   function removeAuthorizedKey(address _key) external onlyAuthorized {
       authorizedKeys[_key] = false;
       emit AuthorizedKeyRemoved(_key);
   }

   function verifyProof(bytes memory _proof, address _publicKey) public override returns (bool) {
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

       if (validProof) {
           authorizedKeys[_publicKey] = true;
           emit AuthorizedKeyAdded(_publicKey);
       }

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
