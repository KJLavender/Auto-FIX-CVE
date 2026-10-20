const test = require("node:test");
const assert = require("node:assert");
const { issue, userFrom } = require("../src/auth");

test("round-trips a user id", () => {
  const token = issue("user-42", "a-long-enough-shared-secret-value");
  assert.strictEqual(userFrom(token, "a-long-enough-shared-secret-value"), "user-42");
});

test("rejects a token signed with another secret", () => {
  const token = issue("user-42", "a-long-enough-shared-secret-value");
  assert.throws(() => userFrom(token, "some-other-secret-value-entirely"));
});
