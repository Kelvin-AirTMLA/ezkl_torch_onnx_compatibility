const Web3 = require('web3');
const web3 = new Web3('https://polygon-rpc.com');

const verifierABI = require('./verifier_abi.json'); // ABI of the verifier contract
const verifierAddress = '0x...'; // Address of the deployed verifier
const verifier = new web3.eth.Contract(verifierABI, verifierAddress);

const proof = require('./proof.json'); // Your EZKL-generated proof
const publicInputs = require('./input.json'); // Your public inputs

verifier.methods.verify(proof, publicInputs).call()
    .then(isValid => {
        if (isValid) {
            console.log('Proof is valid');
            // Proceed with further on-chain actions
        } else {
            console.log('Proof is invalid');
        }
    })
    .catch(error => console.error('Verification failed:', error));