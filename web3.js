// 🌐 Initialize Web3 for Blockchain Interaction
if (typeof window.ethereum !== 'undefined') {
    window.web3 = new Web3(window.ethereum);
    window.ethereum.request({ method: 'eth_requestAccounts' });
} else {
    console.error("❌ MetaMask not detected! Please install MetaMask.");
}

// 🏦 Smart Contract Details
const contractAddress = "0xYourSmartContractAddress";  // Replace with actual contract address
const contractABI = [ /* Paste your Smart Contract ABI here */ ];
const contract = new web3.eth.Contract(contractABI, contractAddress);

// 🔗 Connect Wallet & Display Address
document.getElementById("connectWallet").addEventListener("click", async () => {
    try {
        const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
        document.getElementById("walletAddress").innerText = `Connected: ${accounts[0]}`;
        document.getElementById("walletStatus").innerText = "🟢 Connected";
    } catch (error) {
        console.error("❌ Error connecting wallet:", error);
    }
});

// 🔎 Blockchain Transaction Verification
document.getElementById("verifyBlockchain").addEventListener("click", async () => {
    const txID = document.getElementById("blockchainTxID").value;
    if (!txID) {
        alert("⚠️ Enter a valid Transaction Hash!");
        return;
    }

    try {
        const tx = await web3.eth.getTransaction(txID);
        document.getElementById("blockchainResult").innerText = tx ? "✅ Transaction Verified!" : "❌ Transaction Not Found!";
    } catch (error) {
        console.error("Error verifying transaction:", error);
    }
});
