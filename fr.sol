// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FraudDetectionBanking {
    address public owner;
    uint256 public riskThreshold;  // Risk score threshold to flag suspicious transactions
    mapping(address => uint256) public accountBalances;
    mapping(address => bool) public whitelist;
    mapping(address => bool) public blacklist;
    mapping(address => uint256) public riskScores;
    mapping(address => Transaction[]) public transactionHistory;
    mapping(uint256 => FlaggedTransaction) public flaggedTransactions;

    struct Transaction {
        address from;
        address to;
        uint256 amount;
        uint256 timestamp;
    }

    struct FlaggedTransaction {
        address from;
        address to;
        uint256 amount;
        uint256 riskScore;
        bool reviewed;
        bool fraudConfirmed;
    }

    uint256 public flaggedTransactionCount;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event TransactionFlagged(address indexed from, address indexed to, uint256 amount, uint256 riskScore);
    event FraudConfirmed(address indexed from, address indexed to, uint256 amount);
    event Whitelisted(address indexed user);
    event Blacklisted(address indexed user);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can perform this action");
        _;
    }

    modifier notBlacklisted() {
        require(!blacklist[msg.sender], "Account is blacklisted");
        _;
    }

    constructor(uint256 _riskThreshold) {
        owner = msg.sender;
        riskThreshold = _riskThreshold;
    }

    // Deposit Ether into the banking system
    receive() external payable {
        accountBalances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Withdraw Ether from the banking system
    function withdraw(uint256 _amount) public notBlacklisted {
        require(accountBalances[msg.sender] >= _amount, "Insufficient balance");
        accountBalances[msg.sender] -= _amount;
        payable(msg.sender).transfer(_amount);
        emit Withdraw(msg.sender, _amount);
    }

    // Transfer Ether to another account
    function transfer(address _to, uint256 _amount) public notBlacklisted {
        require(accountBalances[msg.sender] >= _amount, "Insufficient balance");

        // Check if the recipient is blacklisted
        require(!blacklist[_to], "Recipient is blacklisted");

        accountBalances[msg.sender] -= _amount;
        accountBalances[_to] += _amount;
        emit Transfer(msg.sender, _to, _amount);

        // Log the transaction
        Transaction memory newTransaction = Transaction(msg.sender, _to, _amount, block.timestamp);
        transactionHistory[msg.sender].push(newTransaction);
        transactionHistory[_to].push(newTransaction);

        // Evaluate risk for the transaction
        uint256 riskScore = evaluateRisk(msg.sender, _to, _amount);
        riskScores[msg.sender] += riskScore;
        riskScores[_to] += riskScore;

        // Flag the transaction if it exceeds the risk threshold
        if (riskScore >= riskThreshold) {
            flagTransaction(msg.sender, _to, _amount, riskScore);
        }
    }

    // Evaluate the risk score for a transaction (simple example)
    function evaluateRisk(address _from, address _to, uint256 _amount) internal view returns (uint256) {
        uint256 riskScore = 0;

        // Increase risk score for large transactions
        if (_amount > 10 ether) {
            riskScore += 50;
        }

        // Increase risk score for frequent transactions
        if (transactionHistory[_from].length > 10) {
            riskScore += 20;
        }

        // Increase risk score if recipient is not whitelisted
        if (!whitelist[_to]) {
            riskScore += 30;
        }

        return riskScore;
    }

    // Flag suspicious transaction
    function flagTransaction(address _from, address _to, uint256 _amount, uint256 _riskScore) internal {
        flaggedTransactionCount++;
        flaggedTransactions[flaggedTransactionCount] = FlaggedTransaction(
            _from,
            _to,
            _amount,
            _riskScore,
            false,
            false
        );
        emit TransactionFlagged(_from, _to, _amount, _riskScore);
    }

    // Manually review a flagged transaction
    function reviewFlaggedTransaction(uint256 _transactionId, bool _confirmFraud) public onlyOwner {
        require(!flaggedTransactions[_transactionId].reviewed, "Transaction already reviewed");

        flaggedTransactions[_transactionId].reviewed = true;
        flaggedTransactions[_transactionId].fraudConfirmed = _confirmFraud;

        if (_confirmFraud) {
            blacklist[flaggedTransactions[_transactionId].from] = true;
            emit FraudConfirmed(
                flaggedTransactions[_transactionId].from,
                flaggedTransactions[_transactionId].to,
                flaggedTransactions[_transactionId].amount
            );
        }
    }

    // Whitelist a user
    function whitelistUser(address _user) public onlyOwner {
        whitelist[_user] = true;
        emit Whitelisted(_user);
    }

    // Blacklist a user
    function blacklistUser(address _user) public onlyOwner {
        blacklist[_user] = true;
        emit Blacklisted(_user);
    }

    // Adjust the risk threshold
    function setRiskThreshold(uint256 _newThreshold) public onlyOwner {
        riskThreshold = _newThreshold;
    }

    // View transaction history
    function getTransactionHistory(address _user) public view returns (Transaction[] memory) {
        return transactionHistory[_user];
    }

    // View flagged transactions
    function getFlaggedTransaction(uint256 _transactionId) public view returns (FlaggedTransaction memory) {
        return flaggedTransactions[_transactionId];
    }

    // View account balance
    function getAccountBalance(address _user) public view returns (uint256) {
        return accountBalances[_user];
    }
}
