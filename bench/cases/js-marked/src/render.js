const marked = require("marked");

function renderComment(markdown) {
  return marked(markdown, { headerIds: false });
}

module.exports = { renderComment };
