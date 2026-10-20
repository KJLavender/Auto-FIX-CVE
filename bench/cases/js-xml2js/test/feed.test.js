const test = require("node:test");
const assert = require("node:assert");
const { titles } = require("../src/feed");

test("reads item titles from an RSS feed", async () => {
  const xml = "<rss><channel><item><title>One</title></item><item><title>Two</title></item></channel></rss>";
  assert.deepStrictEqual(await titles(xml), ["One", "Two"]);
});
