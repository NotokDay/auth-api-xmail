const mysql = require('mysql2');
const { logger } = require('../utils/logger');
const { DB_HOST, DB_USER, DB_PASS } = require('../utils/secrets');
require('dotenv/config');

const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT
});

connection.connect((err) => {
    if (err) logger.error(err.message);
});

module.exports = connection;
