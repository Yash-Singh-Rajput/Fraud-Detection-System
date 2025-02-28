// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract FraudDetectionSystem {
    address public admin;
    AggregatorV3Interface internal riskOracle;

    enum TransactionStatus { Pending, Verified, Fraudulent, UnderReview, Cleared }
    
    struct Transaction {
        uint256 id;
        address sender;
        address receiver;
        uint256 amount;
        uint256 riskScore;
        bool flagged;
        TransactionStatus status;
        uint256 timestamp;
    }

    struct Dispute {
        uint256 transactionId;
        address complainant;
        string reason;
        bool resolved;
        uint256 votesForFraud;
        uint256 votesForClear;
        mapping(address => bool) voted;
    }

    mapping(uint256 => Transaction) public transactions;
    mapping(uint256 => Dispute) public disputes;
    uint256 public transactionCount;
    uint256 public disputeCount;

    address[] public investigators;
    uint256 public dynamicFraudThreshold = 75; // Can be adjusted based on fraud trends

    event TransactionAnalyzed(uint256 indexed id, address indexed sender, address indexed receiver, uint256 riskScore, bool flagged, uint256 timestamp);
    event FraudAlert(uint256 indexed id, address indexed sender, address indexed receiver, uint256 riskScore, uint256 timestamp);
    event TransactionFlagged(uint256 indexed id, address indexed sender, address indexed receiver, string reason, uint256 timestamp);
    event DisputeOpened(uint256 indexed disputeId, uint256 indexed transactionId, address complainant, string reason);
    event DisputeResolved(uint256 indexed disputeId, uint256 indexed transactionId, bool fraudulent, uint256 timestamp);
    event FraudThresholdUpdated(uint256 newThreshold);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    modifier onlyInvestigator() {
        require(isInvestigator(msg.sender), "Only investigators can vote on disputes");
        _;
    }

    constructor(address _oracleAddress) {
        admin = msg.sender;
        riskOracle = AggregatorV3Interface(_oracleAddress); // AI-powered risk scoring oracle
    }

    function analyzeTransaction(address _receiver, uint256 _amount) public {
        uint256 riskScore = getRiskScoreFromOracle(); // AI-based fraud detection
        transactionCount++;
        bool fraudStatus = riskScore > dynamicFraudThreshold;

        transactions[transactionCount] = Transaction({
            id: transactionCount,
            sender: msg.sender,
            receiver: _receiver,
            amount: _amount,
            riskScore: riskScore,
            flagged: fraudStatus,
            status: fraudStatus ? TransactionStatus.Fraudulent : TransactionStatus.Verified,
            timestamp: block.timestamp
        });

        emit TransactionAnalyzed(transactionCount, msg.sender, _receiver, riskScore, fraudStatus, block.timestamp);
        
        if (fraudStatus) {
            emit FraudAlert(transactionCount, msg.sender, _receiver, riskScore, block.timestamp);
        }
    }

    function flagTransaction(uint256 _id, string memory reason) public {
        require(transactions[_id].id != 0, "Transaction does not exist");
        require(transactions[_id].status == TransactionStatus.Verified, "Transaction already flagged or reviewed");

        transactions[_id].flagged = true;
        transactions[_id].status = TransactionStatus.Fraudulent;

        emit TransactionFlagged(_id, transactions[_id].sender, transactions[_id].receiver, reason, block.timestamp);
    }

    function openDispute(uint256 _transactionId, string memory _reason) public {
        require(transactions[_transactionId].id != 0, "Transaction does not exist");
        require(transactions[_transactionId].flagged, "Transaction must be flagged to dispute");

        disputeCount++;
        Dispute storage newDispute = disputes[disputeCount];
        newDispute.transactionId = _transactionId;
        newDispute.complainant = msg.sender;
        newDispute.reason = _reason;
        newDispute.resolved = false;

        transactions[_transactionId].status = TransactionStatus.UnderReview;

        emit DisputeOpened(disputeCount, _transactionId, msg.sender, _reason);
    }

    function voteOnDispute(uint256 _disputeId, bool voteFraud) public onlyInvestigator {
        Dispute storage dispute = disputes[_disputeId];
        require(!dispute.resolved, "Dispute already resolved");
        require(!dispute.voted[msg.sender], "Investigator has already voted");

        dispute.voted[msg.sender] = true;
        if (voteFraud) {
            dispute.votesForFraud++;
        } else {
            dispute.votesForClear++;
        }

        if (dispute.votesForFraud > investigators.length / 2) {
            resolveDispute(_disputeId, true);
        } else if (dispute.votesForClear > investigators.length / 2) {
            resolveDispute(_disputeId, false);
        }
    }

    function resolveDispute(uint256 _disputeId, bool fraudulent) internal {
        Dispute storage dispute = disputes[_disputeId];
        dispute.resolved = true;
        uint256 transactionId = dispute.transactionId;

        if (fraudulent) {
            transactions[transactionId].status = TransactionStatus.Fraudulent;
        } else {
            transactions[transactionId].status = TransactionStatus.Cleared;
            transactions[transactionId].flagged = false;
        }

        emit DisputeResolved(_disputeId, transactionId, fraudulent, block.timestamp);
    }

    function updateFraudThreshold(uint256 newThreshold) external onlyAdmin {
        require(newThreshold >= 50 && newThreshold <= 90, "Threshold must be between 50-90");
        dynamicFraudThreshold = newThreshold;
        emit FraudThresholdUpdated(newThreshold);
    }

    function addInvestigator(address investigator) external onlyAdmin {
        require(investigator != address(0), "Invalid address");
        investigators.push(investigator);
    }

    function isInvestigator(address _user) public view returns (bool) {
        for (uint i = 0; i < investigators.length; i++) {
            if (investigators[i] == _user) {
                return true;
            }
        }
        return false;
    }

    function getTransaction(uint256 _id) public view returns (address, address, uint256, uint256, bool, TransactionStatus, uint256) {
        Transaction memory txn = transactions[_id];
        require(txn.id != 0, "Transaction does not exist");
        return (txn.sender, txn.receiver, txn.amount, txn.riskScore, txn.flagged, txn.status, txn.timestamp);
    }

    function getRiskScoreFromOracle() internal view returns (uint256) {
        (, int256 answer,,,) = riskOracle.latestRoundData();
        return uint256(answer);
    }

    function updateAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Invalid address");
        admin = newAdmin;
    }
}
