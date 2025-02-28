// Logout Function
document.getElementById("logoutAdmin").addEventListener("click", () => {
    alert("Admin Logged Out");
    window.location.href = "login.html";
});

// Fraud Analysis
document.getElementById("checkFraudAdmin").addEventListener("click", async () => {
    const transactionID = document.getElementById("transactionID").value;

    if (!transactionID) {
        alert("Please enter a Transaction ID!");
        return;
    }

    // Simulating AI Fraud Detection
    const riskScore = Math.floor(Math.random() * 100);
    const isFraud = riskScore > 70;

    document.getElementById("fraudResultAdmin").innerHTML = 
        `Risk Score: ${riskScore}% - ${isFraud ? "🚨 Fraud Detected!" : "✅ Safe Transaction"}`;
});

// Load Users
const users = [
    { id: 1, username: "user1", role: "User" },
    { id: 2, username: "user2", role: "Admin" },
    { id: 3, username: "user3", role: "User" }
];

const userTable = document.getElementById("userTable");
users.forEach(user => {
    const row = `<tr>
        <td>${user.id}</td>
        <td>${user.username}</td>
        <td>${user.role}</td>
        <td><button onclick="removeUser(${user.id})">❌ Remove</button></td>
    </tr>`;
    userTable.innerHTML += row;
});

// Remove User
function removeUser(userId) {
    alert(`User ${userId} removed.`);
}

// Fraud Analytics Chart
const ctx = document.getElementById('fraudChart').getContext('2d');
const fraudChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: ["Jan", "Feb", "Mar", "Apr", "May"],
        datasets: [{
            label: 'Fraud Cases',
            data: [10, 25, 18, 30, 40],
            borderColor: '#ff4500',
            backgroundColor: 'rgba(255, 69, 0, 0.2)',
            borderWidth: 2
        }]
    }
});
