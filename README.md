# Port Scanner

Este é um scanner de portas simples escrito em Python 3. Ele permite que os usuários verifiquem quais portas estão abertas em um determinado host.
---
## Instalação

Antes de executar o programa, é necessário instalar as bibliotecas necessárias. Você pode fazer isso globalmente ou criar um ambiente virtual (venv). As bibliotecas necessárias estão listadas no arquivo requirements.txt.

Para instalar as bibliotecas globalmente, basta executar o seguinte comando:

```sh
pip install -r requirements.txt
``` 

Se você preferir usar um ambiente virtual, siga estes passos:

Crie um ambiente virtual:
```sh
python3 -m venv env
```
Ative o ambiente virtual:
```sh
source env/bin/activate
```

Instale as bibliotecas necessárias:
```sh
pip install -r requirements.txt
``` 
Como Usar

Após instalar as bibliotecas, execute o programa com o seguinte comando:

```sh
sudo python3 scanner.py
```

O comando sudo é necessário porque o programa usa sockets de baixo nível para se comunicar com o sistema operacional. O programa solicitará que você insira o endereço IP do host que deseja verificar e o intervalo de portas a serem verificadas.

O programa então mostrará quais portas estão abertas no host especificado.

# Contribuindo

Se você quiser contribuir para este projeto, sinta-se à vontade para enviar um pull request. Toda ajuda é bem-vinda!
