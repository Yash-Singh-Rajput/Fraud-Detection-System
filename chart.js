const ctx = document.getElementById('fraudChart').getContext('2d');
const fraudChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: ["Jan", "Feb", "Mar", "Apr", "May"],
        datasets: [
            {
                label: 'Fraud Cases',
                data: [10, 25, 18, 30, 40],
                borderColor: '#ff4500',
                backgroundColor: 'rgba(255, 69, 0, 0.5)',
                borderWidth: 2
            },
            {
                label: 'Safe Transactions',
                data: [90, 75, 82, 70, 60],
                borderColor: '#00ff00',
                backgroundColor: 'rgba(0, 255, 0, 0.5)',
                borderWidth: 2
            }
        ]
    },
    options: {
        responsive: true,
        scales: {
            y: {
                beginAtZero: true,
                grid: { color: "rgba(255, 255, 255, 0.2)" }
            },
            x: { grid: { color: "rgba(255, 255, 255, 0.2)" } }
        }
    }
});

// 📈 Dynamic Fraud Data Update
function updateFraudChart(newFraudCases, newSafeTransactions) {
    fraudChart.data.datasets[0].data.push(newFraudCases);
    fraudChart.data.datasets[1].data.push(newSafeTransactions);
    fraudChart.update();
}
