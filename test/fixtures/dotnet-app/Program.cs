using System.Text.Encodings.Web;
using Json = Newtonsoft.Json.JsonConvert;

var encoded = HtmlEncoder.Default.Encode("<b>hi</b>");
var data = Json.DeserializeObject<Dictionary<string, string>>("{\"a\":\"b\"}");
Console.WriteLine($"{encoded} {data?["a"]}");
