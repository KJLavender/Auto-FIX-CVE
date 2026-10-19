const axios = require("axios");

async function fetchUser(id) {
  const res = await axios.get(`/users/${id}`);
  return res.data;
}

module.exports = { fetchUser };
