function validateProof(bytes32 _packetHash, bytes calldata _transactionProof, uint _remoteAddressSize) external view override returns (LayerZeroPacket.Packet memory packet) {
        require(_remoteAddressSize &gt; 0, "ProofLib: invalid address size");
        // _transactionProof = srcUlnAddress (32 bytes) + lzPacket
        require(_transactionProof.length &gt; 32 &amp;&amp; keccak256(_transactionProof) == _packetHash, "ProofLib: invalid transaction proof");

        bytes memory ulnAddressBytes = bytes(_transactionProof[0:32]);
        bytes32 ulnAddress;
        assembly {
            ulnAddress := mload(add(ulnAddressBytes, 32))
        }
        packet = LayerZeroPacket.getPacketV3(_transactionProof[32:], _remoteAddressSize, ulnAddress);

        if (packet.dstAddress == stargateBridgeAddress) packet.payload = _secureStgPayload(packet.payload);
        if (packet.dstAddress == stargateTokenAddress) packet.payload = _secureStgTokenPayload(packet.payload);

        return packet;
    }

    function _secureStgTokenPayload(bytes memory _payload) internal pure returns (bytes memory) {
        (bytes memory toAddressBytes, uint qty) = abi.decode(_payload, (bytes, uint));

        address toAddress = address(0);
        if (toAddressBytes.length &gt; 0) {
            assembly {
                toAddress := mload(add(toAddressBytes, 20))
            }
        }

        if (toAddress == address(0)) {
            address deadAddress = address(0x000000000000000000000000000000000000dEaD);
            bytes memory newToAddressBytes = abi.encodePacked(deadAddress);
            return abi.encode(newToAddressBytes, qty);
        }

        // default to return the original payload
        return _payload;
    }

    function _secureStgPayload(bytes memory _payload) internal view returns (bytes memory) {
        // functionType is uint8 even though the encoding will take up the side of uint256
        uint8 functionType;
        assembly {
            functionType := mload(add(_payload, 32))
        }

        // TYPE_SWAP_REMOTE == 1 &amp;&amp; only if the payload has a payload
        // only swapRemote inside of stargate can call sgReceive on an user supplied to address
        // thus we do not care about the other type functions even if the toAddress is overly long.
        if (functionType == 1) {
            // decode the _payload with its types
            (, uint srcPoolId, uint dstPoolId, uint dstGasForCall, IStargate.CreditObj memory c, IStargate.SwapObj memory s, bytes memory toAddressBytes, bytes memory contractCallPayload) = abi.decode(_payload, (uint8, uint, uint, uint, IStargate.CreditObj, IStargate.SwapObj, bytes, bytes));

            // if contractCallPayload.length &gt; 0 need to check if the to address is a contract or not
            if (contractCallPayload.length &gt; 0) {
                // otherwise, need to check if the payload can be delivered to the toAddress
                address toAddress = address(0);
                if (toAddressBytes.length &gt; 0) {
                    assembly {
                        toAddress := mload(add(toAddressBytes, 20))
                    }
                }

                // check if the toAddress is a contract. We are not concerned about addresses that pretend to be wallets. because worst case we just delete their payload if being malicious
                // we can guarantee that if a size &gt; 0, then the contract is definitely a contract address in this context
                uint size;
                assembly {
                    size := extcodesize(toAddress)
                }

                if (size == 0) {
                    // size == 0 indicates its not a contract, payload wont be delivered
                    // secure the _payload to make sure funds can be delivered to the toAddress
                    bytes memory newToAddressBytes = abi.encodePacked(toAddress);
                    bytes memory securePayload = abi.encode(functionType, srcPoolId, dstPoolId, dstGasForCall, c, s, newToAddressBytes, bytes(""));
                    return securePayload;
                }
            }
        }

        // default to return the original payload
        return _payload;
    }
