const Web3 = require('web3');
const web3 = new Web3(new Web3.providers.HttpProvider('http://192.168.2.110:8545'));
// Replace with actual data
const proposerPrivateKey = '0x...'; // Replace with the proposer's private key
const proposalData = '0x...'; // The data for the proposal
const description = 'Proposal description';
const governanceAbi = [
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "account",
                "type": "address"
            }
        ],
        "name": "isProposer",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "address[]",
                "name": "targets",
                "type": "address[]"
            },
            {
                "internalType": "uint256[]",
                "name": "values",
                "type": "uint256[]"
            },
            {
                "internalType": "bytes[]",
                "name": "calldatas",
                "type": "bytes[]"
            },
            {
                "internalType": "bytes32",
                "name": "descriptionHash",
                "type": "bytes32"
            }
        ],
        "name": "execute",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "payable",
        "type": "function"
    },
    // ... (other parts of the ABI)
];
// Sample SDK functions for Governance contract
const governanceSdk = {
    // Function to propose a new action
    propose: async function (proposerPrivateKey, proposalData, description) {
        // Create a transaction object
        const proposeTx = governanceContract.methods.propose(proposalData, web3.utils.asciiToHex(description));

        // Sign the transaction with the private key of the proposer
        const signedTx = await web3.eth.accounts.signTransaction(
            {
                to: governanceAddress,
                data: proposeTx.encodeABI(),
                gas: await proposeTx.estimateGas({from: proposerAddress}),
            },
            proposerPrivateKey
        );

        // Send the signed transaction
        const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
        console.log('Propose transaction receipt:', receipt);
        return receipt;
    },

    // Function to execute a proposal
    execute: async function (executorPrivateKey, proposalId) {
        // Create a transaction object
        const executeTx = governanceContract.methods.execute(proposalId);

        // Sign the transaction with the private key of the executor
        const signedTx = await web3.eth.accounts.signTransaction(
            {
                to: governanceAddress,
                data: executeTx.encodeABI(),
                gas: await executeTx.estimateGas({from: executorAddress}),
            },
            executorPrivateKey
        );

        // Send the signed transaction
        const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
        console.log('Execute transaction receipt:', receipt);
        return receipt;
    }
};

// Propose an action
governanceSdk.propose(proposerPrivateKey, proposalData, description)
    .then(receipt => console.log('Proposal submitted:', receipt))
    .catch(error => console.error('Error submitting proposal:', error));

//
// const executorPrivateKey = '0x...'; // Replace with the executor's private key
// const proposalId = 1; // The ID of the proposal to execute
//
// // Execute a proposal
// governanceSdk.execute(executorPrivateKey, proposalId)
//     .then(receipt => console.log('Proposal executed:', receipt))
//     .catch(error => console.error('Error executing proposal:', error));
