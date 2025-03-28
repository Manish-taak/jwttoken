const { Sequelize } = require("sequelize");
const config = require("../config/config.json")["development"];

const sequelize = new Sequelize(config.database, config.username, config.password, {
  host: config.host,
  dialect: config.dialect,
});

const db = {};
db.sequelize = sequelize;
db.Sequelize = Sequelize;
db.User = require("./user")(sequelize); // Import the User model

module.exports = db;
