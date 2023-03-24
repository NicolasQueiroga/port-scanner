# Roteiro 2

Tecnologias Hacker

Nicolas Maciel Queiroga

# Introdução

Inicialmente, foi preciso instalar a máquina virtual **Metasploitable2** através do link disponibilizado no guia, que teve que ser convertida em ISO para que fosse possível emular a arquitetura x86 nos Mac’s com **arquitetura ARM**. Concluída esta etapa, a máquina foi incluída na lista de máquinas virtuais disponíveis no **UTM**, utilizando-se a função de Emulação e selecionando-se o arquivo já instalado como disco rígido.

Depois de realizar as configurações necessárias, foi possível fazer login na máquina virtual após iniciá-la, utilizando as credenciais de login ‘msfadmin’. Com a máquina agora funcionando na mesma rede que a máquina virtual Kali Linux, tornou-se viável executar o comando

```bash
sudo netdiscover
```

Este comando possibilita que a máquina Kali Linux descubra o endereço IP da máquina Metasploitable2 na rede, e o endereço IP encontrado deve ser registrado para uso futuro. Após descobrir o endereço IP, é possível utilizar ferramentas como o ***nmap*** para averiguar quais portas estão abertas, o que permite o início dos testes de vulnerabilidade.

A seguir, há uma imagem exibindo todas as máquinas conectadas à mesma rede, permitindo-nos descobrir que a máquina alvo possui o endereço IP 192.168.15.121.

# Exercício 1.1a

![netdiscover.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/netdiscover.png)

Como o MAC Address gerado pela UTM é aleatório, o comando não conseguiu identificar seu vendedor

Agora para descobrir quais são as portas abertas e os serviços rodando nelas, basta executar o seguinte comando:

```bash
sudo nmap -sT 192.168.15.121
```

A seguir estão todas as portas com o protocolo **TCP** abertas na máquina alvo:

![Screenshot 2023-03-23 at 18.17.20.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_18.17.20.png)

Listando o nome e versão do serviço que está rodando exclusivamente na porta 21 com o comando:

```bash
sudo nmap -sV -p 21 -v 192.168.15.121
```

No comando acima, utilizamos a flag ‘**-sV**’ para verificar o serviço que está rodando
na porta indicada pela flag ‘**-p**’ seguida do número da porta.

# Exercício 1.1b

![Screenshot 2023-03-23 at 18.21.49.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_18.21.49.png)

Agora podemos descobrir qual é o nome e versão do sistema operacional que está rodando na máquina alvo com o comando:

```bash
sudo nmap -O 192.168.15.121
```

A seguir pode ser encontrado o resultado da execução do comando anterior, que utiliza a flag **-O** para determinar o sistema operacional da máquina de destino.

# Exercício 1.1c

![Screenshot 2023-03-23 at 18.26.32.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_18.26.32.png)

Acima podemos verificar que o sistema operacional presente na máquina alvo é um **Linux 2.6.X**

Após completar essa etapa, solicitou-se a criação de uma interface Python amigável com as seguintes funcionalidades:

- Possibilidade de escanear um host ou rede.
- Mapear as portas abertas do endereço IP especificado, permitindo ao usuário escolher um único número de porta ou um intervalo de portas.
- Além da função de escaneamento, exibir informações relacionadas aos serviços associados às Portas Bem-Conhecidas.

# Exercício 1.1d

A seguir está o repositório utilizado para construir o **********************PortScanner.**********************

O código contido no repositório poderá rodar apenas em maquinas com Kali Linux devido à restrições de bibliotecas. Dentro do readme terá mais instruções.

[https://github.com/NicolasQueiroga/port-scanner](https://github.com/NicolasQueiroga/port-scanner)

# Exercício 1.1e

Feito isso, podemos agora listar as vulnerabilidades das portas 21 e 445 da máquina alvo utilizando o comando abaixo:

```bash
sudo nmap -p 21,445 --script vuln 192.168.15.121
```

O comando mencionado acima emprega a flag **--script vuln** com o objetivo de detectar possíveis vulnerabilidades nas portas 21 e 445 da máquina alvo. O resultado da execução do comando pode ser visto abaixo:

![Screenshot 2023-03-23 at 18.40.27.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_18.40.27.png)

Como pode ser visto acima, a porta 21 possui uma vulnerabilidade conhecida chamada **vsftpd 2.3.4 Backdoor Command Execution.** Já a porta 445 não possui vulnerabilidades conhecidas.

# Exercício 1.1f

Segue abaixo uma lista de possíveis exploits para as vulnerabilidades encontradas anteriormente:

- Para a vulnerabilidade na **porta 21**, é possível utilizar o exploit **vsftpd 2.3.4 Backdoor Command Execution**, que permite a execução de comandos remotos no sistema alvo.
- Já para a **porta 445**, não foram identificadas vulnerabilidades conhecidas, portanto não há possíveis exploits disponíveis.

# Exercício 1.1g

Com base nas informações dos sites [https://nvd.nist.gov](https://nvd.nist.gov/) e [https://cve.mitre.org](https://cve.mitre.org/), foi possível coletar as seguintes ******CVE****** classificadas como altas para as portas **********3306 e********** 5432:

- **CVE-2016-6662**
    
    **CVE-2016-6662** é uma identificação de uma vulnerabilidade de segurança em software, que ficou conhecida como **MySQL Remote Root Code Execution Vulnerability**. Essa vulnerabilidade permitia a um invasor remoto, sem autenticação, executar código arbitrário no servidor **MySQL vulnerável**. O problema foi descoberto em setembro de 2016 e afetava várias versões do servidor MySQL, incluindo o **MariaDB** e o **Percona** Server. Um patch de segurança foi lançado imediatamente para corrigir a falha, porém, os sistemas que não foram atualizados continuam vulneráveis. Essa **vulnerabilidade é considerada crítica** e pode ser explorada por atacantes para comprometer sistemas que utilizam o MySQL como banco de dados.
    
- **CVE-2018-1058**
    
    **CVE-2018-1058** é uma identificação de uma vulnerabilidade de segurança no componente de autenticação do **OpenSSH**. Essa vulnerabilidade, conhecida como **OpenSSH User Enumeration Timing Attack**, permitia que um atacante remoto determinasse se um usuário existia ou não em um sistema vulnerável usando ataques de temporização. Com essa informação, um atacante poderia, em seguida, usar **ataques de força bruta** para adivinhar a senha do usuário e **obter acesso** não autorizado ao sistema. O problema afetou todas as versões do OpenSSH até a versão 7.7, e **foi corrigido em abril de 2018** com o lançamento da versão 7.7p1. Os usuários são aconselhados a atualizar suas instalações do OpenSSH para a versão mais recente disponível para garantir a segurança do sistema.
    

# Exercício 1.1h

## item a.

Para encontrar o endereço IP de um site ou domínio, basta digitar o comando **nslookup** seguido do **nome do site ou domínio** que deseja consultar. O sistema irá retornar o **endereço IP** associado ao nome do site ou domínio que você digitou.

A seguir, é feito exatamente isso com o site [ietf.org](http://ietf.org):

```bash
nslookup ietf.org
```

![Screenshot 2023-03-23 at 18.57.17.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_18.57.17.png)

## item b.

Para encontrar os servidores ******DNS****** basta utilizar o seguinte comando:

```bash
nslookup -type=ns ierf.org
```

A seguir, o resultado do comando acima:

![Screenshot 2023-03-23 at 19.02.48.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_19.02.48.png)

## item c.

Para poder encontrar se há um servidor de email associado ao domínio **[ietf.org](http://ietf.org)** basta usar o comando abaixo:

```bash
nslookup -type=mx ietf.org
```

O comando acima utiliza a flag **-type=mx** para tentar encontrar servidores de email associados ao domínio solicitado. O resultado do comando pode ser encontrado abaixo:

![Screenshot 2023-03-23 at 19.08.03.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_19.08.03.png)

é possível quer que há um servidor de email **[mail.ietf.org](http://mail.ietf.org)** associado ao
domínio do [ietf.org](http://ietf.org).

Agora utilizando o mesmo comando que usamos para descobrir o ****IP**** no ************item a************, temos o seguinte resultado:

```bash
nslookup mail.ietf.org
```

![Screenshot 2023-03-23 at 19.16.49.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_19.16.49.png)

O **endereço IP** associado ao servidor de email é o **50.223.129.194**.

## Exercício 1.1i

Utilizando como escolha para os exercícios a seguir o site [www.apple.com](http://www.apple.com), temos:

## item a.

Os servidores DNS responsáveis por esse domínio são:

![Screenshot 2023-03-23 at 19.19.27.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_19.19.27.png)

## item b.

Para descobrir se há outros domínios ou serviços hospedados no mesmo IP basta usar os seguintes comandos:

```bash
host apple.com
```

![Screenshot 2023-03-23 at 19.21.03.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_19.21.03.png)

E então, podemos utilizar qualquer ****IP**** presente do output do comando com o mesmo comando ********host********:

![Screenshot 2023-03-23 at 19.24.14.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_19.24.14.png)

O resultado da execução do comando indica que o endereço IP 17.253.144.10 tem um nome de domínio associado "[apple.com](http://apple.com/)". Portanto, o resultado significa que o endereço **IP** 17.253.144.10 pertence ao domínio "[apple.com](http://apple.com/)".

## item c.

Para descobrir o sistema operacional rodando em uma determinada máquina de um determinado IP, basta executar o comando utilizado anteriormente neste roteiro:

```bash
nmap -O apple.com
```

![Screenshot 2023-03-23 at 19.30.38.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_19.30.38.png)

A saída apresenta uma lista de suposições agressivas sobre o sistema operacional (OS) que pode estar sendo executado na máquina alvo. Cada suposição é acompanhada de uma porcentagem que indica a confiança do sistema em sua estimativa.

As suposições indicam que o sistema pode estar executando uma variedade de sistemas operacionais diferentes, como Crestron XPanel, ASUS RT-N56U WAP, Linux 3.1, Linux 3.16, Linux 3.2, HP P2000 G3 NAS device, AXIS 210A ou 211 Network Camera, Linux 4.10, entre outros.

No entanto, a saída também indica que não há uma correspondência exata com o sistema operacional da máquina alvo, e as condições do teste não são ideais. Isso pode significar que a suposição do sistema operacional é menos precisa ou confiável do que o desejado, o que pode exigir a realização de testes adicionais para determinar com mais precisão qual sistema operacional está sendo executado na máquina alvo.

Agora, para encontrar o servidor WEB que hospeda esse site podemos usar o comando:

```bash
curl -I apple.com
```

![Screenshot 2023-03-23 at 19.32.53.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_19.32.53.png)

Não foi possível identificar diretamente o servidor web que está sendo utilizado pelo site [apple.com](http://apple.com). No entanto, é possível inferir algumas informações a partir da resposta:

- O cabeçalho **`Via`** indica que a conexão foi realizada através do proxy **`brsao4-edge-bx-001.ts.apple.com`**, que provavelmente pertence à Apple. Isso sugere que a Apple pode estar usando um servidor proxy para distribuir o tráfego do site.
- A resposta inclui um cabeçalho **`CDNUUID`**, que geralmente é usado para identificar o objeto em cache em um servidor de conteúdo de rede (CDN). Isso também sugere que a Apple pode estar usando uma CDN para distribuir o conteúdo do site.

No entanto, sem acesso direto ao servidor ou informações adicionais, não é possível identificar com certeza qual servidor web está sendo usado pelo site apple.com.

Para descobrir quando foram feitas as últimas alterações em um site como [apple.com](http://apple.com/), basta utilizando ferramentas online como o site **[https://www.changedetection.com](https://www.changedetection.com/)** que monitora mudanças em sites e envia notificações por e-mail quando há alterações.

## item d.

Existem algumas ferramentas de linha de comando que podem ser usadas para descobrir as tecnologias utilizadas por um domínio, como por exemplo:

```bash
whatweb apple.com
```

![Screenshot 2023-03-23 at 19.49.59.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_19.49.59.png)

Ao acessar o site em sua versão segura (https), é possível observar que o servidor HTTP utilizado é o "Apple" e que a página utiliza **HTML5** e diversos scripts, como **application/json**, **application/ld+json** e **text/javascript**. Além disso, o site possui **políticas de segurança**, como o **Strict-Transport-Security** e **X-Frame-Options**, e usa um recurso chamado **Open-Graph-Protocol**. Através da tecnologia **Akamai**, o site também usa um **cache**, conforme identificado pelo **X-Cache** na saída do comando.

## item e.

O **`wafw00f`** é uma ferramenta de linha de comando que pode ser usada para identificar se um site é protegido por um Web Application Firewall (WAF). Para verificar se o site apple.com está protegido por um WAF usando o **`wafw00f`**, você pode executar o seguinte comando:

```bash
wafw00f apple.com
```

A saída do comando irá indicar se o site está protegido por um WAF e, se sim, qual é o WAF que está sendo usado.

![Screenshot 2023-03-23 at 19.58.26.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_19.58.26.png)

Isso indica que o **`wafw00f`**não conseguiu determinar qual WAF está sendo usado, pois pode haver um IDS/IPS bloqueando a detecção de WAF.

## item f.

Caso existam, podemos encontrar os servidores de email com o mesmo comando utilizado anteriormente neste roteiro:

```bash
nslookup -type=mx apple.com
```

![Screenshot 2023-03-23 at 20.01.12.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_20.01.12.png)

Acima há 6 servidores de email encontrados. Abaixo estão os seus respectivos IP’s:

![Screenshot 2023-03-23 at 20.13.50.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_20.13.50.png)

# Exercício 1.1j

![Screenshot 2023-03-23 at 23.26.29.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_23.26.29.png)

![Screenshot 2023-03-23 at 23.27.00.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_23.27.00.png)

![Screenshot 2023-03-23 at 23.43.54.png](Roteiro%202%20486c74ac67c84552b38e027c46688c37/Screenshot_2023-03-23_at_23.43.54.png)

Utilizando o programa feito por mim, é possível inserir qualquer IP em qualquer subnet para escanear a rede. Feito isso, e escolhendo o IP que queira investigar, basta alterar o campo para digitar o IP com o novo valor, e, se quiser, selecionar um range de portas a serem escaneadas. Tendo então o resultado de portas vulneráveis.

Conforme mencionado em uma questão anterior, foi identificada uma vulnerabilidade conhecida na porta 21, denominada "Execução de Comandos Backdoor vsftpd 2.3.4". Além das CVEs previamente mencionadas, outras também afetam esta porta. 

- A CVE-2011-2523, que impacta o vsftpd 2.3.4 e possibilita que um invasor remoto execute comandos arbitrários com as permissões do usuário que está executando o servidor FTP.
- Outra CVE relevante é a CVE-2020-15870, que afeta o vsftpd 3.0.3 e permite a um invasor autenticado executar comandos arbitrários com as permissões do usuário que está executando o servidor FTP.