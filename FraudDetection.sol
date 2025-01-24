// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AdvancedFraudDetection {

    struct Transaction {
        address from;
        address to;
        uint256 amount;
        uint256 timestamp;
        bool isFraudulent;
    }

    Transaction[] public transactions;
    mapping(address => uint256) public balances;
    uint256 public fraudThreshold = 10 ether; // Default threshold

    event TransactionProcessed(address indexed from, address indexed to, uint256 amount, bool isFraudulent);
    event FraudDetected(address indexed account, uint256 amount, uint256 timestamp);
    event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);

    // Admin address
    address public admin;

    constructor() {
        admin = msg.sender; // Set the deployer as the admin
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    // Deposit funds
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Transfer funds with fraud detection
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        bool isFraudulent = false;
        if (amount > fraudThreshold) {
            isFraudulent = true;
            emit FraudDetected(msg.sender, amount, block.timestamp);
        }

        balances[msg.sender] -= amount;
        balances[to] += amount;

        transactions.push(Transaction({
            from: msg.sender,
            to: to,
            amount: amount,
            timestamp: block.timestamp,
            isFraudulent: isFraudulent
        }));

        emit TransactionProcessed(msg.sender, to, amount, isFraudulent);
    }

    // Update fraud detection threshold (only admin)
    function updateThreshold(uint256 newThreshold) public onlyAdmin {
        uint256 oldThreshold = fraudThreshold;
        fraudThreshold = newThreshold;
        emit ThresholdUpdated(oldThreshold, newThreshold);
    }

    // Get all transactions
    function getAllTransactions() public view returns (Transaction[] memory) {
        return transactions;
    }
}

