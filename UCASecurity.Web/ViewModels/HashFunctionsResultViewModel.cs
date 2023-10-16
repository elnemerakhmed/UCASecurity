using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Web.ViewModels
{
    public class HashFunctionsResultViewModel
    {
        [JsonPropertyName("md5")]
        public Result<string> MD5 { get; set; }
        [JsonPropertyName("ripmed160")]
        public Result<string> RIPMED160 { get; set; }
        [JsonPropertyName("sha1")]
        public Result<string> SHA1 { get; set; }
        [JsonPropertyName("sha256")]
        public Result<string> SHA256 { get; set; }
        [JsonPropertyName("sha512")]
        public Result<string> SHA512 { get; set; }
        [JsonPropertyName("tiger")]
        public Result<string> Tiger { get; set; }
        [JsonPropertyName("whirlpool")]
        public Result<string> Whiirlpool { get; set; }
    }
}
