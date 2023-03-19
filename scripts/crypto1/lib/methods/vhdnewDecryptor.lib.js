/*
* vhdDecryptor module
* Description: Yeah, this module aims to decrypt configs made by Art Of Tunnel dev team.
* Author: PANCHO7532, research: @HACK_K
*
* WARNING: This module is in a beta phase forked directly from evozi algorithm,
* this may not work for all versions and you would end trying it using /raw
*/
const metadata = {
    "title":"vhdDecryptor",
    "author":"HACK_K",
    "version":1,
    "schemeLength":1
}
const crypto = require('crypto');
const fs = require('fs');
module.exports.metadata = metadata;
function parseDecoded(data) {
    //console.log(JSON.parse(data)["outboundBean"]);
    //console.log(JSON.parse(data)["outboundBean"]["mux"]);
    //console.log(JSON.parse(data)["outboundBean"]["streamSettings"]);
    let jObject = {};
    let responseObject = {};
    try {
        jObject = JSON.parse(data);
    } catch(err) {
        jObject["note1"] = "Something went wrong";
    }
    responseObject["connectionMethod"] = jObject["configType"];
    responseObject["build"] = jObject["build"];
    try { responseObject["created"] = new Date(jObject["addedTime"]).toUTCString(); } catch(e) {};
    try { responseObject["enableExpire"] = jObject["iuhuwfiub"].toString() } catch(e) {};
    try { responseObject["expireDate"] = jObject["usbdfiidf"].toString() } catch(e) {};
    try { responseObject["hwidEnabled"] = jObject["iubsiudfbju"].toString() } catch(e) {};
    responseObject["hwidValue"] = jObject["hooiqwdnio"];
    try { responseObject["mobileData"] = jObject["ksdfibsdf"].toString() } catch(e) {};
    try { responseObject["passwordProtected"] = jObject["pjwniefdio"].toString() } catch(e) {};
    responseObject["passwordValue"] = jObject["hbhbshd"];
    try { responseObject["googlePlay"] = jObject["pwefiniosdf"].toString() } catch(e) {};
    try { responseObject["blockedRoot"] = jObject["onwefiub"].toString() } catch(e) {};
    responseObject["V2RayURL"] = jObject["configUrl"];
    if(jObject["outboundBean"]) {
        responseObject["V2RayProtocol"] = jObject["outboundBean"]["protocol"];
        if(jObject["outboundBean"]["settings"]) {
            if(jObject["outboundBean"]["settings"]["vnext"]) {
                for(let c = 0; c < jObject["outboundBean"]["settings"]["vnext"].length; c++) {
                    responseObject["V2RayHost"] = jObject["outboundBean"]["settings"]["vnext"][c]["address"];
                    try { responseObject["V2RayPort"] = jObject["outboundBean"]["settings"]["vnext"][c]["port"].toString(); } catch(e) {};
                    responseObject["V2RayTLS"] = jObject["outboundBean"]["settings"]["vnext"][c]["sni"];
                    for(let d = 0; d < jObject["outboundBean"]["settings"]["vnext"][c]["users"].length; d++) {
                        responseObject["V2RayUserId"] = jObject["outboundBean"]["settings"]["vnext"][c]["users"][d]["id"];
                        responseObject["V2RayAlterId"] = jObject["outboundBean"]["settings"]["vnext"][c]["users"][d]["alterId"];
                    }
                }
            }
        }
        if(jObject["outboundBean"]["streamSettings"]) {
            responseObject["V2RayNetwork"] = jObject["outboundBean"]["streamSettings"]["network"];
            responseObject["V2RaySecurity"] = jObject["outboundBean"]["streamSettings"]["security"];
            if(jObject["outboundBean"]["streamSettings"]["tlsSettings"]) {
                responseObject["V2RayTLSInsecure"] = jObject["outboundBean"]["streamSettings"]["tlsSettings"]["allowInsecure"];
                responseObject["V2RayTLS"] = jObject["outboundBean"]["streamSettings"]["tlsSettings"]["serverName"];
            }
            if(jObject["outboundBean"]["streamSettings"]["wsSettings"]) {
                try { responseObject["V2RayHeaders"] = JSON.stringify(jObject["outboundBean"]["streamSettings"]["wsSettings"]["headers"]); } catch(err) {};
                responseObject["V2RayWSPath"] = jObject["outboundBean"]["streamSettings"]["wsSettings"]["path"];
            }
        }
        if(jObject["outboundBean"]["mux"]) {
            try { responseObject["V2RayMux"] = jObject["outboundBean"]["mux"]["enabled"].toString(); } catch(e) {}
            try { responseObject["V2RayMuxConcurrency"] = jObject["outboundBean"]["mux"]["concurrency"].toString(); } catch(e) {};
        }
    }
    //console.log(responseObject);
    return JSON.stringify(responseObject);
}
function aesDecrypt(data, key, iv) {
    /*console.log("data:");
    console.log(data);
    console.log("key:");
    console.log(key);
    console.log(key.toString());
    console.log("iv:");
    console.log(iv);
    console.log(iv.toString());*/
    let result;
    const aesOperation = crypto.createDecipheriv("aes-128-cbc", key, iv);
    result = aesOperation.update(data, "base64", "utf-8");
    //console.log(result);
    result += aesOperation.final("utf-8");
    return result;
}
function decryptStage(fileContent, configFile) {
    //oh boi, here we go
    var keyFile, IVs;
    var complete = false;
    var response = {};
    response["content"] = "";
    response["raw"] = "";
    response["error"] = 0;
    fileContent = fileContent.toString().replace(/[\n]/g, "");
    try {
        keyFile = JSON.parse(fs.readFileSync(configFile["keyFile"]).toString())["vhdd"][0];
        IVs = JSON.parse(fs.readFileSync(configFile["keyFile"]).toString())["vhdd"][1];
    } catch(error) {
        response["error"] = error;
        return response;
    }
    //decrypting stage
    var preDecodedContent = "";
    for(let c = 0; c < keyFile.length; c++) {
        let complete1 = false;
        for(let d = 0; d < IVs.length; d++) {
            //console.log("first stage:");
            //console.log("using key1: " + keyFile[c]);
            //console.log("using iv: " + IVs[d]);
            try {
                preDecodedContent = aesDecrypt(fileContent, Buffer.from(keyFile[c]), Buffer.from(IVs[d]));
                complete1 = true;
                //console.log("complete");
                //console.log(preDecodedContent);
                break;
            } catch(error) { /*console.log("failed")*/ /*console.log(error)*/ }
        }
        if(complete1) { complete = true; /*console.log("complete, so break");*/ break; }
    }
    if(complete) {
        //console.log(response);
        response["content"] = preDecodedContent;
        response["raw"] = response["content"];
        response["content"] = parseDecoded(response["content"]);
        try { response["raw"] = JSON.parse(response["content"])["raw"] } catch(e) {}
        //console.log(response);
        return response;
    } else {
        //console.log(response);
        response["error"] = 1;
        return response;
    }
}
module.exports.decryptFile = function(file, configFile, type) {
    // This function acts like a "hub" between the decoding methods, less fashioned that the other solution, but hopefully can work.
    var defaultApiError = {};
    defaultApiError["content"] = "";
    defaultApiError["raw"] = "";
    defaultApiError["error"] = 1;
    switch(type) {
        case 0:
            return decryptStage(file, configFile);
        default:
            return defaultApiError;
    }
}
//hello