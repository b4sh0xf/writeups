# wcorp: hard, windows, 700xp
<img alt="Logo" src="https://app.hackingclub.com/media/logos/hc.svg" class="h-35px logo">

## vulns: `asrep roasting`, `kereroasting`, `bad dacls`

## 1️⃣ recon

- como não temos credenciais, começamos enumerando o smb com o usuário `guest` sem senha
    
    <img width="1531" height="927" alt="image" src="https://github.com/user-attachments/assets/5fad9340-94af-451d-9416-fbbb4cb7d5e9" />

- não encontramos nada de interessante nos shares em si, mas com esse usuário conseguimos enumerar alguns outros usuários do `ad` com a flag `--rid-brute`

## 2️⃣ fuzzing

- podemos montar uma lista com esses usuários e tentar fazer um [as-rep roasting](https://www.notion.so/0x07-active-directory-203e253790968041a319ce0cddb067fc?pvs=21) e capturar algum hash krbgt
    
    <img width="1920" height="339" alt="image" src="https://github.com/user-attachments/assets/200be58b-76e2-4bb9-9bba-4f9d8a6b1f10" />

    
- agora podemos tentar quebrar esse hash para conseguir acesso à essa conta de serviço
    
    <img width="1920" height="514" alt="image" src="https://github.com/user-attachments/assets/170f4032-6a35-419a-8c8e-6b120cc8481b" />

    
- com isso conseguimos as credenciais `svc_backup:LuvinJames<3`, o que nos permite conseguir a primeira flag
    
    <img width="1920" height="348" alt="image" src="https://github.com/user-attachments/assets/e8e31bb5-a099-4ebd-932c-1cb1c2b786a3" />

    
- para continuar a exploração, podemos fazer o ldap dump e analisá-lo no bloodhound
    
    <img width="1914" height="691" alt="image" src="https://github.com/user-attachments/assets/98994a9a-2652-47f3-bb6a-e7d1e33fe404" />

    
- nosso usuário atual não tem nada de interessante, no entanto, descobrimos que a conta `svc_web` é kerberoastable, ou seja, conseguimos dumpar seu hash krbgt
    
    <img width="1911" height="334" alt="image" src="https://github.com/user-attachments/assets/f614f568-e13a-4e6d-a8ae-549352fdc9e9" />

    
- quebrando esse hash, conseguimos acesso às credenciais `svc_web:J&J=1331ch`
    
    <img width="1911" height="688" alt="image" src="https://github.com/user-attachments/assets/bb502285-40f2-4fa9-8fba-37b8551c9c95" />

    
- voltando ao bloodhound, vemos que esse usuário possui GenericWrite sobre o `john.doe`, o que nos permite performar um ataque de shadow credentials e capturar o seu nt hash
    
    <img width="1362" height="728" alt="image" src="https://github.com/user-attachments/assets/163c9848-1583-46f8-8b28-077af3994f4b" />

    
- capturando o nt hash
    
    <img width="1521" height="475" alt="image" src="https://github.com/user-attachments/assets/6e8d6dcd-200a-4b94-af50-e6cbcf225e37" />

    

## 3️⃣ rce

- o usuário `john.doe` foi o primeiro a fazer parte do grupo Remote Management, mas em nenhum momento eu acessei o winrm com ele, pois voltei ao bloodhound e verifiquei que ele possuia DCSync sobre o dominio, o que nos permite capturar o hash do Administrator
    
    <img width="1496" height="709" alt="image" src="https://github.com/user-attachments/assets/b2afc3f5-9584-4dc4-a0a4-2dacc98a9ac9" />

    

## 4️⃣ privesc

- capturando o hash
    
    <img width="1529" height="334" alt="image" src="https://github.com/user-attachments/assets/cd2e8741-a40b-4b79-b1f8-6569631b8d6b" />

    
- pegando a última flag (depois de mais de um mês pq a maquina tava quebrada)
    
    <img width="1529" height="334" alt="image" src="https://github.com/user-attachments/assets/a9ddac72-daad-4f65-a5cb-9b862ac0d139" />
