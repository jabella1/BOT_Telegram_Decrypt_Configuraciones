
/*
 * /==================================================\
 * | New SocksHTTP decryptor                          |
 * | Copyright (c) PANCHO7532, HACK_K - 2022                  |
 * |==================================================/
 * |-> Purpose ➤ Decryption tool
 * |-> Decrypted at ➤ 18/02/2022 22:34 PM [GMT-3] (approx)
 * |-> Algorithm ➤ JSON > Base64 > AES-CBC-256 + MD5 > Plain JSON syntax
 * ----------------------------------------------------
 */
var path = require("path")
const {createDecipheriv, createHash} = require("crypto");
const {readFileSync, existsSync} = require("fs");
if(!process.argv[2] || !existsSync(process.argv[2])) { console.log("[ERROR] Unspecified path/file"); process.exit(1); }
var file=process.argv[2]
//console.log(file)
if(path.parse(file).ext != ".sks"){

return;}
try { JSON.parse(readFileSync(process.argv[2]).toString()) } catch(e) { console.log("[ERROR] Invalid JSON data!"); //process.exit(1)
return;}
let configFile = JSON.parse(readFileSync(process.argv[2]).toString());
const configKeys = [
    //"dyv35182!",
    //"dyv35224nossas!!",
    "662ede816988e58fb6d057d9d85605e0", //hardcoded key, probably for sksplus, goes raw as string, used when version is less than 5
    "162exe235948e37ws6d057d9d85324e2", //gck() used on current configs, appended " 5" then md5 encoded
    "962exe865948e37ws6d057d4d85604e0", //gck2() key for sksplus, goes raw as string in version=5, else it appends " [whatever version is on 'v' json value]" and re-encodes to md5
    "175exe868648e37wb9x157d4l45604l0", //gdk() probably used for encrypt securepreferences on app storage, append either ➤ " AppPreferences" or " ProfileSshPreferences", encode with MD5 and ready to go
    "175exe867948e37wb9d057d4k45604l0", //gdk2() unused, but probably for the same purpose than gdk() in a future or past
];
function aesDecrypt(data, key, iv) {
    const aesInstance = createDecipheriv("aes-256-cbc", Buffer.from(key, "base64"), Buffer.from(iv, "base64"));
    let result = aesInstance.update(data, "base64", "utf-8");
    result += aesInstance.final("utf-8");
    return result;
}
function md5crypt(data) {
    return createHash("md5").update(data).digest("hex");
}
function parseConfig(data) {
    console.log(`【𝐉𝐅】Host SSH ➤ ${data.sshServer}`);
    console.log(`【𝐉𝐅】Puerto SSH ➤ ${data.sshPort}`);
    console.log(`【𝐉𝐅】Usuario SSH ➤ ${data.profileSshAuth.sshUser}`);
    if(!!data.profileSshAuth.sshPasswd) { console.log(`【𝐉𝐅】Contra SSH ➤ ${data.profileSshAuth.sshPasswd}`); }
    if(!!data.profileSshAuth.sshPublicKey) { console.log(`【𝐉𝐅】Public Key:\n${data.profileSshAuth.sshPublicKey}`); }
    if(!!data.enableDataCompression) { console.log(`【𝐉𝐅】Enable data compression ➤ ${data.enableDataCompression}`); }
    if(!!data.disableTcpDelay) { console.log(`【𝐉𝐅】Disable TCP Delay ➤ ${data.disableTcpDelay}`); }
    if(!!data.proxyType) {
        console.log(`【𝐉𝐅】Connection type ➤ ${
            data.proxyType == "PROXY_HTTP" ? "SSH + HTTP":
            data.proxyType == "PROXY_SSL" ? "SSH + SSL/TLS" : "Undefined"
        }`);
    } else {
        console.log(`【𝐉𝐅】Connection type ➤ SSH DIRECT`);
    }
    if(!!data.proxyHttp) {
        if(!!data.proxyHttp.proxyIp) { console.log(`【𝐉𝐅】Proxy ➤ ${data.proxyHttp.proxyIp}`); }
        if(!!data.proxyHttp.proxyPort) { console.log(`【𝐉𝐅】Puerto Proxy ➤ ${data.proxyHttp.proxyPort}`); }
        if(!!data.proxyHttp.isCustomPayload) { console.log(`【𝐉𝐅】Use custom payload para proxy ➤ ${data.proxyHttp.isCustomPayload}`); }
        if(!!data.proxyHttp.customPayload) { console.log(`【𝐉𝐅】Proxy Payload:\n${data.proxyHttp.customPayload}`); }
    }
    if(!!data.proxySsl) {
        if(!!data.proxySsl.hostSni) { console.log(`【𝐉𝐅】SSL/SNI ➤ ${data.proxySsl.hostSni}`); }
        if(!!data.proxySsl.versionSSl) { console.log(`【𝐉𝐅】SSL Version ➤ ${data.proxySsl.versionSSl}`); }
        if(!!data.proxySsl.isSSLCustomPayload) { console.log(`【𝐉𝐅】Usa custom payload para SSL ➤ ${data.proxySsl.isSSLCustomPayload}`); }
        if(!!data.proxySsl.customPayloadSSL) { console.log(`【𝐉𝐅】SSL Payload:\n${data.proxySsl.customPayloadSSL}`); }
    }
    if(!!data.proxyDirect) {
        if(!!data.proxyDirect.isCustomPayload) { console.log(`【𝐉𝐅】Custom payload ➤ ${data.proxyDirect.isCustomPayload}`); }
        if(!!data.proxyDirect.customPayload) { console.log(`【𝐉𝐅】Payload ➤ ${data.proxyDirect.customPayload}`); }
    }
    if(!!data.dnsCustom) { console.log(`【𝐉𝐅】Custom DNS Servers ➤ ${JSON.stringify(data.dnsCustom)}`)}
    if(!!data.isUdpgwForward) { console.log(`【𝐉𝐅】Forward UDP via UDPGW ➤ ${data.isUdpgwForward}`)}
    if(!!data.configProtect) {
        if(!!data.configProtect.blockConfig) { console.log(`【𝐉𝐅】Bloqueo config ➤ ${data.configProtect.blockConfig}`)}
        if(!!data.configProtect.validity) { console.log(`【𝐉𝐅】Fecha expiracion ➤ ${new Date(data.configProtect.validity).toString()}`)}
        if(!!data.configProtect.blockRoot) { console.log(`【𝐉𝐅】Bloqueo root ➤ ${data.configProtect.blockRoot}`)}
        if(!!data.configProtect.blockAuthEdition) { console.log(`【𝐉𝐅】Bloqueo non-PlayStore app ➤ ${data.configProtect.blockAuthEdition}`)}
        if(!!data.configProtect.onlyMobileData) { console.log(`【𝐉𝐅】Use only mobile data ➤ ${data.configProtect.onlyMobileData}`)}
        if(!!data.configProtect.blockByPhoneId) { console.log(`【𝐉𝐅】HWID Activado ➤ ${data.configProtect.blockByPhoneId}`)}
        if(!!data.configProtect.message) { console.log(`【𝐉𝐅】Notas ➤ \n${data.configProtect.message}`)}
        if(!!data.configProtect.phoneId) { console.log(`【𝐉𝐅】Valor HWID ➤ ${data.configProtect.phoneId}`)}
        if(!!data.configProtect.hideMessageServer) { console.log(`【𝐉𝐅】Hide mensaje server SSH ➤ ${data.configProtect.hideMessageServer}`)}
        return;
    }
    
}

try {
    parseConfig(
        JSON.parse(
            aesDecrypt(
                configFile.d.split(".")[0],
                Buffer.from(md5crypt(configKeys[1] + " " + configFile.v)).toString("base64"),
                configFile.d.split(".")[1]
            )
        )
    );
} catch(e) { console.log(`[ERROR] Decryption failed! ${e}`); }
