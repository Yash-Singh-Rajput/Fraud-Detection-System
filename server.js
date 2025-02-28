const express = require("express");
const app = express();
app.use(express.json());

app.post("/analyze", (req, res) => {
    const { transactionID } = req.body;
    const riskScore = Math.floor(Math.random() * 100);
    res.json({ transactionID, riskScore, isFraud: riskScore > 70 });
});

app.listen(3000, () => console.log("Server running on port 3000"));
