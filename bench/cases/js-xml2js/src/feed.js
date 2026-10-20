const xml2js = require("xml2js");

async function titles(xml) {
  const doc = await xml2js.parseStringPromise(xml);
  return doc.rss.channel[0].item.map((item) => item.title[0]);
}

module.exports = { titles };
