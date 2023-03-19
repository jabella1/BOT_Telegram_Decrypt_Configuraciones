
#!/usr/bin/python


#recordar instalar

# pip install 'git+https://github.com/jashandeep-sohi/python-blowfish.git'
# pip3 install pycryptodome
from config import *
import requests
import telebot #manejar la API de telegram


from Crypto.Cipher import Blowfish

from pathlib import Path
import base64

import os
from time import sleep
from shutil import which
from sys import stdin, stdout, stderr
from pathlib import Path
from base64 import b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad




bot = telebot.TeleBot(TOKEN_BOT_DECRYPTSSH)

os.umask(0)


class contador:
    def __init__(self) -> None:
        self.__numero = 0
        self.__numero2 = 0
    def obtenerNumero1(self):
        return self.__numero
    def obtenerNumero2(self):
        return self.__numero2
    def aumentarNumero1(self):
        self.__numero = self.__numero + 1
    def aumentarNumero2(self):
        self.__numero2 = self.__numero2 + 1
        
objContador = contador()

@bot.message_handler(commands=['start'])
def mensajeInicial(message):
    bot.send_message(message.chat.id,"Hola perro.\nEnvia tus archivos .ssh - .tnl - .sks - .nm - .tvt - .rez - .tmt - .cnet - .sksrv - .fnet")
    bot.send_message(CHAT_ID_DECRYPT_LOGS,"El usuario: "+message.chat.username+" con chatID: "+str(message.chat.id)+" ha iniciado el bot.")
    

@bot.message_handler(content_types=["photo"])
def mensajeRespuestaFotos(message):
    bot.send_message(message.chat.id,"No envies fotos hpta.")


@bot.message_handler(content_types=["document"])
def desencriptarArchivos(mensajeUsuario):
    os.chdir(RUTA_BOT)
    if ".ssh" in mensajeUsuario.document.file_name or ".SSH" in mensajeUsuario.document.file_name:

        try:
            file_info = bot.get_file(mensajeUsuario.document.file_id)

            file = requests.get('https://api.telegram.org/file/bot{0}/{1}'.format(TOKEN_BOT_DECRYPTSSH, file_info.file_path))

            key = str.encode("263386285977449155626236830061505221752")

            cipherText = base64.b64decode(file._content.decode("utf-8"))
            iv = cipherText[:Blowfish.block_size]
            cipherText = cipherText[Blowfish.block_size:]
            cipher = Blowfish.new(key,Blowfish.MODE_CBC, iv)
            message = cipher.decrypt(cipherText)
            last_byte = message[-1]
            message = message[: - (last_byte if type(last_byte) is int else ord(last_byte))]

            bot.send_message(mensajeUsuario.chat.id, message.decode("utf-8").replace("<entry key=","【𝐉𝐅】").
                             replace('rsion="1.0" encoding="UTF-8"?>',"").
                             replace('<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">',"").
                             replace("<properties>","").
                             replace("<comment>SSH Injector</comment>","▶▶▶▶▶𝐃𝐞𝐜𝐫𝐲𝐩𝐭◀◀◀◀◀\nby: @JuanFCol\n\n").
                             replace('"file.msg">',"Nota ➤ ").
                             replace('"file.msg"/>',"Nota ➤ ").
                             replace('"file.root">',"Bloqueo root ➤ ").
                             replace('"file.mobileData">',"Bloqueo datos moviles ➤ ").
                             replace('"proxyAuth">',"Proxy auth ➤ ").
                             replace('"file.secure">',"Archivo bloqueado ➤ ").
                             replace('"tlsVersion">',"Version tls ➤ ").
                             replace('"usarDefaultPayload">',"Payload por defecto ➤ ").
                             replace('"file.keepLogin">',"KeepLogin ➤ ").
                             replace('"cdnssshPass"/>',"CdnsSshPass ➤ ").
                             replace('"cdnssshPass">',"CdnsSshPass ➤ ").
                             replace('"dnsKey"/>',"DnsKey ➤ ").
                             replace('"dnsKey">',"DnsKey ➤ ").
                             replace('"sshPort">',"Puerto SSH ➤ ").
                             replace('"sshPort"/>',"Puerto SSH ➤ ").
                             replace('"udpResolver">',"UDP ➤ ").
                             replace('"proxyRemotoPorta"/>',"Puerto proxy remoto ➤ ").
                             replace('"serverMsg"/>',"Server mensaje ➤ ").
                             replace('"sshPortaLocal">',"Puerto local SSH ➤ ").
                             replace('"proxyPayload">',"Payload ➤ ").
                             replace('"proxyPayload"/>',"Payload ➤ ").
                             replace('"dnsResolver2">',"DnsResolver2 ➤ ").
                             replace('"dnsResolver">',"DnsResolver ➤ ").
                             replace('"sslProxy">',"SNI ➤ ").
                             replace('"sslProxy"/>',"SNI ➤ ").
                             replace('"hideServer">',"Hide Server_msj log ➤ ").
                             replace('"sshUser">',"Usuario SSH ➤ ").
                              replace('"sshUser"/>',"Usuario SSH ➤ ").
                             replace('"proxyPass"/>',"Proxy contra ➤ ").
                             replace('"file.sniff">',"AntiSniff ➤ ").
                             replace('"cdnssshUser"/>',"CdnsSshUser ➤ ").
                             replace('"cdnssshUser">',"CdnsSshUser ➤ ").
                             replace('"file.password"/>',"Contra archivo ➤ ").
                             replace('"sshServer">',"Servidor SSH ➤ ").
                             replace('"sshServer"/>',"Servidor SSH ➤ ").
                             replace('"file.hardwareId"/>',"Hardware ID ➤ ").
                             replace('"data_compression">',"Compresion de datos ➤ ").
                             replace('"chaveKey"/>',"Public key ➤ ").
                             replace('"chaveKey">',"Public key ➤ ").
                             replace('"file.hardwareIdLogin">',"Login hardware ID ➤ ").
                             replace('"udpForward">',"UdpForward ➤ ").
                             replace('"file.appVersionCode">',"Version app ➤ ").
                             replace('"dnsForward">',"DnsForward ➤ ").
                             replace('"file.ps">',"Archivo ps ➤ ").
                             replace('"tunnelType">',"Tipo tunel ➤ ").
                             replace('"buildin">',"Buildin ➤ ").
                             replace('"file.torrent">',"Bloqueo torrent ➤ ").
                             replace('"serverNameKey"/>',"NameServer ➤ ").
                             replace('"serverNameKey">',"NameServer ➤ ").
                             replace('"file.expire">',"Fecha expiracion ➤ ").
                             replace('"proxyUser"/>',"Usuario proxy ➤ ").
                             replace('"proxyRemoto"/>',"Proxy remoto ➤ ").
                             replace('"unlockKeys">',"UnlockKeys ➤ ").
                             replace('"sshPass">',"Contra SSH ➤ ").
                             replace('"sshPass"/>',"Contra SSH ➤ ").
                             replace('"file.disableInbuild">',"Build desactivada ➤ ").
                             replace('</entry>',"\n⇲⇲⇲⇲⇲⇲⇲⇲⇲⇲\n").
                             replace('</properties>',"\n▶▶▶▶▶𝐃𝐞𝐜𝐫𝐲𝐩𝐭◀◀◀◀◀")
                             )
            
            bot.send_message(CHAT_ID_DECRYPT_LOGS,"El usuario: "+mensajeUsuario.chat.username+" con chatID: "+str(mensajeUsuario.chat.id)+" ha desencriptado un archivo .ssh : \n\n"+message.decode("utf-8").replace("<entry key=","【𝐉𝐅】").
                             replace('rsion="1.0" encoding="UTF-8"?>',"").
                             replace('<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">',"").
                             replace("<properties>","").
                             replace("<comment>SSH Injector</comment>","▶▶▶▶▶𝐃𝐞𝐜𝐫𝐲𝐩𝐭◀◀◀◀◀\nby: @JuanFCol\n\n").
                             replace('"file.msg">',"Nota ➤ ").
                             replace('"file.msg"/>',"Nota ➤ ").
                             replace('"file.root">',"Bloqueo root ➤ ").
                             replace('"file.mobileData">',"Bloqueo datos moviles ➤ ").
                             replace('"proxyAuth">',"Proxy auth ➤ ").
                             replace('"file.secure">',"Archivo bloqueado ➤ ").
                             replace('"tlsVersion">',"Version tls ➤ ").
                             replace('"usarDefaultPayload">',"Payload por defecto ➤ ").
                             replace('"file.keepLogin">',"KeepLogin ➤ ").
                             replace('"cdnssshPass"/>',"CdnsSshPass ➤ ").
                             replace('"cdnssshPass">',"CdnsSshPass ➤ ").
                             replace('"dnsKey"/>',"DnsKey ➤ ").
                             replace('"dnsKey">',"DnsKey ➤ ").
                             replace('"sshPort">',"Puerto SSH ➤ ").
                             replace('"sshPort"/>',"Puerto SSH ➤ ").
                             replace('"udpResolver">',"UDP ➤ ").
                             replace('"proxyRemotoPorta"/>',"Puerto proxy remoto ➤ ").
                             replace('"serverMsg"/>',"Server mensaje ➤ ").
                             replace('"sshPortaLocal">',"Puerto local SSH ➤ ").
                             replace('"proxyPayload">',"Payload ➤ ").
                             replace('"proxyPayload"/>',"Payload ➤ ").
                             replace('"dnsResolver2">',"DnsResolver2 ➤ ").
                             replace('"dnsResolver">',"DnsResolver ➤ ").
                             replace('"sslProxy">',"SNI ➤ ").
                             replace('"sslProxy"/>',"SNI ➤ ").
                             replace('"hideServer">',"Hide Server_msj log ➤ ").
                             replace('"sshUser">',"Usuario SSH ➤ ").
                             replace('"sshUser"/>',"Usuario SSH ➤ ").
                             replace('"proxyPass"/>',"Proxy contra ➤ ").
                             replace('"file.sniff">',"AntiSniff ➤ ").
                             replace('"cdnssshUser"/>',"CdnsSshUser ➤ ").
                             replace('"cdnssshUser">',"CdnsSshUser ➤ ").
                             replace('"file.password"/>',"Contra archivo ➤ ").
                             replace('"sshServer">',"Servidor SSH ➤ ").
                             replace('"sshServer"/>',"Servidor SSH ➤ ").
                             replace('"file.hardwareId"/>',"Hardware ID ➤ ").
                             replace('"data_compression">',"Compresion de datos ➤ ").
                             replace('"chaveKey"/>',"Public key ➤ ").
                             replace('"chaveKey">',"Public key ➤ ").
                             replace('"file.hardwareIdLogin">',"Login hardware ID ➤ ").
                             replace('"udpForward">',"UdpForward ➤ ").
                             replace('"file.appVersionCode">',"Version app ➤ ").
                             replace('"dnsForward">',"DnsForward ➤ ").
                             replace('"file.ps">',"Archivo ps ➤ ").
                             replace('"tunnelType">',"Tipo tunel ➤ ").
                             replace('"buildin">',"Buildin ➤ ").
                             replace('"file.torrent">',"Bloqueo torrent ➤ ").
                             replace('"serverNameKey"/>',"NameServer ➤ ").
                             replace('"serverNameKey">',"NameServer ➤ ").
                             replace('"file.expire">',"Fecha expiracion ➤ ").
                             replace('"proxyUser"/>',"Usuario proxy ➤ ").
                             replace('"proxyRemoto"/>',"Proxy remoto ➤ ").
                             replace('"unlockKeys">',"UnlockKeys ➤ ").
                             replace('"sshPass">',"Contra SSH ➤ ").
                             replace('"sshPass"/>',"Contra SSH ➤ ").
                             replace('"file.disableInbuild">',"Build desactivada ➤ ").
                             replace('</entry>',"\n⇲⇲⇲⇲⇲⇲⇲⇲⇲⇲\n").
                             replace('</properties>',"\n▶▶▶▶▶𝐃𝐞𝐜𝐫𝐲𝐩𝐭◀◀◀◀◀")
                             )
        except:
            bot.send_message(mensajeUsuario.chat.id,"Ocurrio un error al tratar de desencriptar el archivo.")
            bot.send_message(CHAT_ID_DECRYPT_LOGS,"Al usuario: "+mensajeUsuario.chat.username+" con chatID: "+str(mensajeUsuario.chat.id)+" se le presento un error al tratar de desencriptar un archivo .ssh")
    elif ".tnl" in mensajeUsuario.document.file_name or ".TNL" in mensajeUsuario.document.file_name:
            file_info = bot.get_file(mensajeUsuario.document.file_id)

            file = requests.get('https://api.telegram.org/file/bot{0}/{1}'.format(TOKEN_BOT_DECRYPTSSH, file_info.file_path))

          #  key = str.encode("263386285977449155626236830061505221752")

            try:
                desencriptarTNL(mensajeUsuario,file._content.decode("utf-8"))
            except:
                bot.send_message(mensajeUsuario.chat.id,"Ocurrio un error al tratar de desencriptar el archivo.")
                bot.send_message(CHAT_ID_DECRYPT_LOGS,"Al usuario: "+mensajeUsuario.chat.username+" con chatID: "+str(mensajeUsuario.chat.id)+" se le presento un error al tratar de desencriptar un archivo .tnl")

    elif ".sksrv" in mensajeUsuario.document.file_name or ".SKSRV" in mensajeUsuario.document.file_name:
        juanFColDecrypt2(mensajeUsuario,".sksrv")
    elif ".sks" in mensajeUsuario.document.file_name or ".SKS" in mensajeUsuario.document.file_name:
        juanFColDecrypt(mensajeUsuario,".sks")
    elif ".nm" in mensajeUsuario.document.file_name or ".NM" in mensajeUsuario.document.file_name:
        juanFColDecrypt(mensajeUsuario,".nm")
    elif ".tvt" in mensajeUsuario.document.file_name or ".TVT" in mensajeUsuario.document.file_name:
        juanFColDecrypt(mensajeUsuario,".tvt")
    elif ".rez" in mensajeUsuario.document.file_name or ".REZ" in mensajeUsuario.document.file_name:
        juanFColDecrypt(mensajeUsuario,".rez")
    elif ".tmt" in mensajeUsuario.document.file_name or ".TMT" in mensajeUsuario.document.file_name:
        juanFColDecrypt2(mensajeUsuario,".tmt")
    elif ".cnet" in mensajeUsuario.document.file_name or ".CNET" in mensajeUsuario.document.file_name:
        juanFColDecrypt2(mensajeUsuario,".cnet")
    elif ".fnet" in mensajeUsuario.document.file_name or ".FNET" in mensajeUsuario.document.file_name:
        juanFColDecrypt2(mensajeUsuario,".fnet")
    #elif ".hat" in mensajeUsuario.document.file_name or ".HAT" in mensajeUsuario.document.file_name:
    #    juanFColDecrypt(mensajeUsuario,".hat")
    else:
        bot.send_message(mensajeUsuario.chat.id,"Solo se permiten archivos con extension .ssh - .tnl - .sks - .nm - .tvt - .rez - .tmt - .cnet - .sksrv - .fnet")
        bot.send_message(CHAT_ID_DECRYPT_LOGS,"El usuario: "+mensajeUsuario.chat.username+" con chatID: "+str(mensajeUsuario.chat.id)+" mando un archivo no permitido")

    #print(file._content.decode("utf-8"))

#DESENCRIPTAR TNL

# pass
#PASSWORDS = { 
#    '.tnl': b'B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg',  #✓
#}

def juanFColDecrypt2(mensajeUsuario,prmExtension):
    #crypto1
    try:
        objContador.aumentarNumero2()

        file_info = bot.get_file(mensajeUsuario.document.file_id)

        file = requests.get('https://api.telegram.org/file/bot{0}/{1}'.format(TOKEN_BOT_DECRYPTSSH, file_info.file_path))

        file_name = mensajeUsuario.document.file_name

        downloaded_file = bot.download_file(file_info.file_path)

        f = open("./scripts/archivos/"+str(objContador.obtenerNumero2())+prmExtension, "w")
            
        with f as new_file:
            new_file.write(downloaded_file.decode("utf-8"))
        new_file.close()

        os.chdir('./scripts/crypto1')

        desencriptado = os.popen('node legendecryptor.js ../archivos/'+str(objContador.obtenerNumero2())+prmExtension).read()

        os.remove('../archivos/'+str(objContador.obtenerNumero2())+prmExtension)

        bot.send_message(mensajeUsuario.chat.id, desencriptado)
        bot.send_message(CHAT_ID_DECRYPT_LOGS,"El usuario: "+mensajeUsuario.chat.username+" con chatID: "+str(mensajeUsuario.chat.id)+" ha desencriptado un archivo "+prmExtension+" :\n\n"+desencriptado)
    except:
        bot.send_message(mensajeUsuario.chat.id,"Ocurrio un error al tratar de desencriptar el archivo, recuerda poner un nombre simple en el archivo. Sin caracteres o emojis.")
        bot.send_message(CHAT_ID_DECRYPT_LOGS,"Al usuario: "+mensajeUsuario.chat.username+" con chatID: "+str(mensajeUsuario.chat.id)+" se le presento un error al tratar de desencriptar un archivo "+prmExtension)

def juanFColDecrypt(mensajeUsuario,prmExtension):
    #crypto
    try:
        objContador.aumentarNumero1()

        file_info = bot.get_file(mensajeUsuario.document.file_id)

        file = requests.get('https://api.telegram.org/file/bot{0}/{1}'.format(TOKEN_BOT_DECRYPTSSH, file_info.file_path))

        file_name = mensajeUsuario.document.file_name

        downloaded_file = bot.download_file(file_info.file_path)

        f = open("./scripts/archivos/"+str(objContador.obtenerNumero1())+prmExtension, "w")
            
        with f as new_file:
            new_file.write(downloaded_file.decode("utf-8"))
        new_file.close()

        os.chdir('./scripts/crypto')

        desencriptado = os.popen('node legendecryptor.js ../archivos/'+str(objContador.obtenerNumero1())+prmExtension).read()

        os.remove('../archivos/'+str(objContador.obtenerNumero1())+prmExtension)        
        bot.send_message(mensajeUsuario.chat.id, desencriptado)
        bot.send_message(CHAT_ID_DECRYPT_LOGS,"El usuario: "+mensajeUsuario.chat.username+" con chatID: "+str(mensajeUsuario.chat.id)+" ha desencriptado un archivo "+prmExtension+" :\n\n"+desencriptado)
    except:
        bot.send_message(mensajeUsuario.chat.id,"Ocurrio un error al tratar de desencriptar el archivo, recuerda poner un nombre simple en el archivo. Sin caracteres o emojis.")
        bot.send_message(CHAT_ID_DECRYPT_LOGS,"Al usuario: "+mensajeUsuario.chat.username+" con chatID: "+str(mensajeUsuario.chat.id)+" se le presento un error al tratar de desencriptar un archivo "+prmExtension)

def error(error_msg = 'Corrupted/unsupported file.'):
    stderr.write(f'\033[41m\033[30m X \033[0m {error_msg}\n')
    stderr.flush()

    exit(1)

def warn(warn_msg):
    stderr.write(f'\033[43m\033[30m ! \033[0m {warn_msg}\n')
    stderr.flush()

def ask(prompt):
    stderr.write(f'\033[104m\033[30m ? \033[0m {prompt} ')
    stderr.flush()

    return input()

def human_bool_to_bool(human_bool):
    return 'y' in human_bool

def desencriptarTNL(messageUsuario,Archivo):
    

    encrypted_contents = Archivo

    split_base64_contents = encrypted_contents.split('.')


    split_contents = list(map(b64decode, split_base64_contents))

    decryption_key = PBKDF2('B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg', split_contents[0], hmac_hash_module=SHA256)

    cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=split_contents[1])
    decrypted_contents = cipher.decrypt_and_verify(split_contents[2][:-16], split_contents[2][-16:])

   
        
    config = decrypted_contents.decode('utf-8','ignore')


    encabezado = "\n▶▶▶▶▶𝐃𝐞𝐜𝐫𝐲𝐩𝐭◀◀◀◀◀\n\n By: @JuanFCol\n\n"
        
    #message = "\n▶▶▶▶▶𝐃𝐞𝐜𝐫𝐲𝐩𝐭◀◀◀◀◀\n\n" 
    #message +=" By: @JuanFCol\n\n"
    message = ""
    sshadd ='';port ='';user='';passw=''
    configdict ={}
    for line in config.split('\n'):
        if line.startswith('<entry'):
            line = line.replace('<entry key="','')
            line = line.replace('</entry','')
            line = line.split('">')
            if len(line) >1:
                configdict[line[0]] = line[1].strip(">")
            else:
                configdict[line[0].strip('"/>')]= " Nel"
        			#print(f'[>] {line} ==> X')
    for k,v in configdict.items():
        if k in ["sshServer","sshPass","sshUser","sshPort","proxyPayload","sslHost"]: 
            continue
        else:
            if k == "sshPortLocal":
                k = "Puerto local"
            elif k == "userDefaultPayload":
                k = "Payload por defecto"
            elif k == "file.protection":
                k= "Archivo bloqueado"
            elif k=="udpForward":
                k == "UdpForward"
            elif k == "proxyRemote":
                k = "Proxy remoto"
        #    elif k == "proxyPayload":
        #        k = "Payload"
            elif k == "file.msg":
                k = "Notas"
            elif k == "proxyRemotePort":
                k = "Puerto proxy remoto"
            elif k == "userProxyAuthentication":
                k = "Usuario auth proxy"
            elif k == "dnsForward":
                k="DnsForward"
            elif k=="file.appVersionCode":
                k="Version app"
            elif k == "udpResolver":
                k = "UdpResolver"
            elif k == "dnsResolver":
                k = "DnsResolver"
            elif k == "tunnelType":
                k = "Tipo de tunel"
            elif k == "file.validate":
                k = "Fecha expiracion"
            elif k == "dnsnameserver":
                k = "NameServer"
            elif k == "dnsst":
                k = "DNSST"
            elif k == "dnspu":
                k = "DNSPU"
            elif k == "file.askLogin":
                k = "Ask Login"
            elif k == "cUUID":
                k = "Valor HWID"
            elif k == "LockHost":
                k = "Bloqueo host"
         #   elif k == "sslHost":
         #       k = "SNI"
            elif k == "proxypass":
                k = "Contra proxy"
            elif k == "sslProtocol":
                k = "Protocolo SSL"
            elif k == "checkRoot":
                k = "Bloqueo root"
            elif k == "proxyuser":
                k = "Usuario proxy"
            elif k == "loginHome":
                k = "LoginHome"
            if(v == "0"):
                v = "Nel"
            elif(v == "1"):
                v = "Sisa"
            elif(v == "*******"):
                v="Nel"
            if message == "":
                message = f'【𝐉𝐅】{k} ➤ {v}\n⇲⇲⇲⇲⇲⇲⇲⇲⇲⇲\n'
            else:
                message += f'【𝐉𝐅】{k} ➤ {v}\n⇲⇲⇲⇲⇲⇲⇲⇲⇲⇲\n'                
    message = encabezado + f'【𝐉𝐅】SSH ➤ \n{configdict["sshServer"]}:{configdict["sshPort"]}@{configdict["sshUser"]}:{configdict["sshPass"]}\n⇲⇲⇲⇲⇲⇲⇲⇲⇲⇲\n'+'【𝐉𝐅】Payload ➤ '+configdict["proxyPayload"]+'\n⇲⇲⇲⇲⇲⇲⇲⇲⇲⇲\n'+'【𝐉𝐅】SNI ➤ '+configdict["sslHost"]+'\n⇲⇲⇲⇲⇲⇲⇲⇲⇲⇲\n' + message    	
    message += "\n▶▶▶▶▶𝐃𝐞𝐜𝐫𝐲𝐩𝐭◀◀◀◀◀"
    bot.send_message(messageUsuario.chat.id,message)
    bot.send_message(CHAT_ID_DECRYPT_LOGS,"El usuario: "+messageUsuario.chat.username+" con chatID: "+str(messageUsuario.chat.id)+" ha desencriptado un archivo .tnl : \n\n"+message)
    #print(message)
   

#DESENCRIPTAR TNL


#MAIN
if __name__ == '__main__':   
    print('Iniciando el bot')
    bot.infinity_polling() #esperar mensajes infinito