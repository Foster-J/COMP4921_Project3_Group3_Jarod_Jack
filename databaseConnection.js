const fs = require('fs');
const mysql = require('mysql2/promise');

const dbConfig = {
    host: process.env.MYSQL_HOST,
    port: process.env.MYSQL_PORT,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,
    ssl: {
        ca: fs.readFileSync(process.env.MYSQL_SSL_CA),
        rejectUnauthorized: true,
    },
    multipleStatements: true,
};

async function testConnection() {
    try {
        const connection = await mysql.createConnection(dbConfig);
        console.log("Connected to Aiven MySQL successfully!");
        await connection.query("SELECT 1");
        await connection.end();
    } catch (err) {
        console.error("Error connecting to Aiven MySQL:", err.message);
    }
}

testConnection();

module.exports = mysql.createPool(dbConfig);