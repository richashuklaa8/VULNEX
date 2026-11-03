// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuditRegistry {

    struct Attestation {
        bytes32 reportHash;
        bytes32 contractHash;
        address auditor;
        uint256 timestamp;
        uint256 blockNumber;
    }

    mapping(bytes32 => Attestation) public attestations;

    event Attested(
        bytes32 indexed reportHash,
        bytes32 indexed contractHash,
        address indexed auditor
    );

    function attest(
        bytes32 reportHash,
        bytes32 contractHash
    ) external {

        attestations[reportHash] = Attestation({
            reportHash: reportHash,
            contractHash: contractHash,
            auditor: msg.sender,
            timestamp: block.timestamp,
            blockNumber: block.number
        });

        emit Attested(
            reportHash,
            contractHash,
            msg.sender
        );
    }

    function verify(
        bytes32 reportHash
    ) external view returns (
        bytes32,
        bytes32,
        address,
        uint256,
        uint256
    ) {
        Attestation memory a = attestations[reportHash];

        return (
            a.reportHash,
            a.contractHash,
            a.auditor,
            a.timestamp,
            a.blockNumber
        );
    }
}
