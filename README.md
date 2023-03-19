# Bot Telegram

Este bot de telegram tiene como objetivo desencriptar configuraciones de archivos de diferentes VPN, las extensiones permitidas y compatibles son:
.ssh - .tnl - .sksrv - .sks - .nm - .tvt - .rez - .tmt - .cnet - .fnet

## Dependencias necesarias
```
Ejecute primero los siguientes comandos:

1.  sudo apt-get update
2.  sudo apt-get upgrade

Asegurese de tener instaladas las siguientes dependencias en su servidor:

3.  sudo apt-get install python3

Ahora asegurese de que se haya instalado una version de python mayor o igual a la 3.8, con el siguiente comando:

4.  python3 --version

Despues de asegurarse de que la version sea mayor o igual a la 3.8, continua con el siguiente comando:

5.  pip3 install pyTelegramBotAPI

6.  pip3 install 'git+https://github.com/jashandeep-sohi/python-blowfish.git'

7.  pip3 install pycryptodome

```
## Configuracion necesaria
```
Ubiquese en el archivo config.py

1.  En la variable TOKEN_BOT_DECRYPTSSH debe configurar el token de su bot.

TOKEN_BOT_DECRYPTSSH = "su_token"

2.  En la variable RUTA_BOT debe digitar la ruta en donde se encuentra el bot

RUTA_BOT = "RutaActual"

3.  El bot se debe agregar a un grupo el cual servira como logs, es decir, a ese grupo le llegara toda la informacion cuando alguien inicie el bot,
    cuando envie un archivo o cuando se le presente algun error, dicho lo anterior, en la variable CHAT_ID_DECRYPT_LOGS, debe digitar la ID del chat
    
    CHAT_ID_DECRYPT_LOGS = "ID_chat_donde_se_agrego_el_bot"
```
## Ejecucion
```
Para ejecutar el bot debera ejecutar el siguiente comando:

1. python3 BotDesencriptarJuanFCol.py &

Recordando que el "&" es para que se ejecute en segundo plano, es decir, que pueda dejar en ejecucion el bot en algun servidor.

Nota: tenga en cuenta que si tiene diferentes versiones de python3 y una de ellas es inferior a la version 3.8 se le puede presentar algun error, por tanto
usted en el comando puede especificar la version 3.8+ que instalo anteriormente de la siguiente manera:

python3.8 BotDesencriptarJuanFCol.py &

o

python3.11 BotDesencriptarJuanFCol.py &
etc...

Acorde a la version que tenga.

```


