using System.Reflection;
using System.Runtime.Loader;
using System.Text.Json.Nodes;
using ServiceLib.Common;
using ServiceLib.Enums;
using ServiceLib.Handler;
using ServiceLib.Handler.Fmt;
using ServiceLib.Models.Configs;
using ServiceLib.Models.CoreConfigs;
using ServiceLib.Models.Entities;
using ServiceLib.Services.CoreConfig;

var client = Path.GetFullPath(args[0]);
AssemblyLoadContext.Default.Resolving += (_, name) =>
{
    var path = Path.Combine(client, name.Name + ".dll");
    return File.Exists(path) ? AssemblyLoadContext.Default.LoadFromAssemblyPath(path) : null;
};
await Probe.Run(args[1], args[2]);

static class Probe
{
    public static async Task Run(string work, string pin)
    {
        var config = ConfigHandler.LoadConfig() ?? throw new Exception("default config failed");
        // '+' must survive one query decode; this test does not depend on random cert bytes.
        const string special = "+/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        foreach (var protocol in new[] { "hy2", "tuic" })
        {
            var encoded = await Import(protocol, special, config);
            Check(encoded.CertSha == special, protocol + " encoded + / = preserved");
        }

        var cases = new[] {
            ("hy2", "c_pin.json", 1081, pin, false, 24443),
            ("hy2", "c_nopin.json", 1082, "", false, 24443),
            ("hy2", "c_wrongpin.json", 1083, new string('A', 43) + "=", false, 24443),
            ("tuic", "t_pin.json", 1084, pin, false, 24444),
            ("hy2", "c_insec.json", 1085, "", true, 24443),
            ("hy2", "c_deadport.json", 1086, "", true, 24499),
            ("tuic", "t_nopin.json", 1087, "", false, 24444),
            ("tuic", "t_wrongpin.json", 1089, new string('A', 43) + "=", false, 24444),
        };
        foreach (var (protocol, file, port, certPin, insecure, remotePort) in cases)
        {
            var node = await Import(protocol, certPin, config);
            node.Port = remotePort;
            if (insecure) node.AllowInsecure = "true";
            Check(string.IsNullOrEmpty(node.Cert), file + " no PEM");
            var outbound = Generate(config, node);
            var tls = outbound["tls"]!.AsObject();
            if (certPin.Length > 0)
            {
                Check(tls["certificate_public_key_sha256"]?[0]?.GetValue<string>() == certPin,
                      file + " actual DLL emitted pin");
                Check(tls["insecure"]!.GetValue<bool>() == false && tls["certificate"] == null,
                      file + " pin overrides insecure; no certificate conflict");
            }
            else Check(tls["certificate_public_key_sha256"] == null, file + " pin absent");
            var json = new JsonObject {
                ["log"] = new JsonObject { ["level"] = "warn" },
                ["inbounds"] = new JsonArray(new JsonObject {
                    ["type"] = "socks", ["listen"] = "127.0.0.1", ["listen_port"] = port }),
                ["outbounds"] = new JsonArray(outbound)
            };
            File.WriteAllText(Path.Combine(work, file), json.ToJsonString());
        }
        var pemNode = await Import("hy2", pin, config);
        pemNode.Cert = File.ReadAllText(Path.Combine(work, "pki/cert.crt"));
        var pemTls = Generate(config, pemNode)["tls"]!;
        Check(pemTls["certificate"] != null && pemTls["certificate_public_key_sha256"] == null,
              "existing PEM takes precedence without conflicting pin");
        Console.WriteLine("PASS  client import + actual ServiceLib outbound generation");
    }

    static async Task<ProfileItem> Import(string protocol, string pin, Config config)
    {
        string authority = protocol == "hy2" ? "testpw" : "11111111-1111-1111-1111-111111111111:testpw";
        var link = $"{protocol}://{authority}@127.0.0.1:24443?sni=www.bing.com&alpn=h3&congestion_control=bbr";
        if (pin.Length > 0) link += "&pinSHA256=" + Uri.EscapeDataString(pin);
        var node = protocol == "hy2" ? Hysteria2Fmt.Resolve(link, out _) : TuicFmt.Resolve(link, out _);
        if (node == null) throw new Exception("link rejected: " + protocol);
        var result = protocol == "hy2"
            ? await ConfigHandler.AddHysteria2Server(config, node, false)
            : await ConfigHandler.AddTuicServer(config, node, false);
        Check(result == 0, protocol + " import normalization");
        return node;
    }

    static JsonObject Generate(Config config, ProfileItem node)
    {
        var service = new CoreConfigSingboxService(new CoreConfigContext {
            Node = node, AppConfig = config, RunCoreType = ECoreType.sing_box, IsLinux = true });
        // Same outbound builder called by GenerateClientConfigContent; reflection avoids live app state.
        var build = typeof(CoreConfigSingboxService).GetMethod("BuildProxyServer", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new Exception("upstream outbound API changed");
        var result = build.Invoke(service, null) ?? throw new Exception("outbound missing");
        return JsonNode.Parse(JsonUtils.Serialize(result))!.AsObject();
    }

    static void Check(bool condition, string name)
    {
        if (!condition) throw new Exception(name);
    }
}
