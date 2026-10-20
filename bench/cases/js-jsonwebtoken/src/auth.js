const jwt = require("jsonwebtoken");

function issue(userId, secret) {
  return jwt.sign({ sub: userId }, secret, { expiresIn: "1h" });
}

function userFrom(token, secret) {
  return jwt.verify(token, secret).sub;
}

module.exports = { issue, userFrom };
