const test = require("node:test");
const assert = require("node:assert");
const { renderComment } = require("../src/render");

test("renders headings and emphasis", () => {
  const html = renderComment("# Title\n\nsome *text*");
  assert.match(html, /<h1>Title<\/h1>/);
  assert.match(html, /<em>text<\/em>/);
});
