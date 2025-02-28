const alertBox = document.getElementById("alertBox");

// 🚨 Trigger Fraud Alerts
function showFraudAlert(transactionID, riskScore) {
    const alertMessage = document.createElement("div");
    alertMessage.classList.add("fraud-alert");
    alertMessage.innerHTML = `
        <p>🚨 Fraud Alert: Transaction <b>${transactionID}</b></p>
        <p>Risk Score: <b>${riskScore}%</b></p>
    `;
    alertBox.prepend(alertMessage);

    // Auto-remove alert after 10 seconds
    setTimeout(() => alertMessage.remove(), 10000);
}

// 🎯 Simulating Incoming Alerts
setInterval(() => {
    const randomID = `TX${Math.floor(Math.random() * 10000)}`;
    const randomRisk = Math.floor(Math.random() * 100);
    if (randomRisk > 75) showFraudAlert(randomID, randomRisk);
}, 15000);
