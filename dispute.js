document.addEventListener("DOMContentLoaded", () => {
    loadDisputes();
});

const disputes = [
    { id: 1, transactionID: "TX12345", complainant: "0xUser1", reason: "Suspicious Activity", status: "Under Review", votesFraud: 2, votesClear: 3 },
    { id: 2, transactionID: "TX67890", complainant: "0xUser2", reason: "Unauthorized Payment", status: "Pending", votesFraud: 1, votesClear: 1 }
];

// Load disputes dynamically
function loadDisputes() {
    const disputeTable = document.getElementById("disputeTable");
    disputeTable.innerHTML = "";

    disputes.forEach(dispute => {
        const row = `<tr>
            <td>${dispute.id}</td>
            <td>${dispute.transactionID}</td>
            <td>${dispute.complainant}</td>
            <td>${dispute.reason}</td>
            <td class="status-${dispute.status.toLowerCase()}">${dispute.status}</td>
            <td>🚨 ${dispute.votesFraud} | ✅ ${dispute.votesClear}</td>
            <td>
                <button onclick="resolveDispute(${dispute.id}, true)">✅ Approve</button>
                <button onclick="resolveDispute(${dispute.id}, false)">❌ Reject</button>
            </td>
        </tr>`;
        disputeTable.innerHTML += row;
    });
}

// Handle dispute voting
document.getElementById("voteFraud").addEventListener("click", () => {
    voteOnDispute(true);
});

document.getElementById("voteClear").addEventListener("click", () => {
    voteOnDispute(false);
});

function voteOnDispute(voteFraud) {
    const disputeID = document.getElementById("voteDisputeID").value;
    if (!disputeID) {
        document.getElementById("voteResult").innerText = "❌ Enter a valid Dispute ID!";
        return;
    }

    const message = voteFraud ? "Voted as Fraudulent!" : "Voted as Safe!";
    document.getElementById("voteResult").innerText = `✅ Dispute #${disputeID} - ${message}`;
}
