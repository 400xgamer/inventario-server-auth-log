# Inventário - 3F Resinados

Projeto Node + Express que serve uma interface estática em `public/` e uma API que persiste em `data.json`.

Avisos rápidos:
- O arquivo `data.json` contém dados locais; por segurança, ele está listado em `.gitignore` por padrão.
- Em produção considere migrar `data.json` para um banco (Deta, Supabase, etc.) e definir `SESSION_SECRET` via variável de ambiente.

Como preparar e subir para o GitHub (passos locais):

1. Instale dependências:

```bash
npm install
```

2. Inicialize e faça o commit (local):

```bash
git init
git add .
git commit -m "Initial commit"
```

3a. Criar repositório remoto via GitHub (web):
- Crie um novo repo em https://github.com/new
- Copie a URL remota e execute:

```bash
git branch -M main
git remote add origin https://github.com/SEU_USUARIO/SEU_REPO.git
git push -u origin main
```

3b. (Alternativa) Usando GitHub CLI (`gh`):

```bash
gh auth login
gh repo create NOME-DO-REPO --public --source=. --remote=origin --push
```

Execução em hosts grátis (resumo):
- Para teste rápido: Replit (suporta Node e mantém workspace com `data.json`). Defina `DISABLE_HTTPS=1` e `TRUST_PROXY=1` nas variáveis de ambiente do Replit.
- Para frontend apenas: Cloudflare Pages / GitHub Pages (faça deploy da pasta `public/`).

Variáveis de ambiente importantes:
- `DISABLE_HTTPS=1` — roda em HTTP (útil onde o host faz TLS termination).
- `TRUST_PROXY=1` — ajusta `trust proxy` para cookies quando atrás de proxy.
- `SESSION_SECRET` — segredo para sessions (defina um valor forte em produção).

Se quiser, eu posso:
- (A) Inicializar o repositório Git local e fazer o commit aqui (posso executar os comandos), ou
- (B) Apenas te guiar passo a passo enquanto você executa, ou
- (C) Tentar criar o repositório remoto com `gh` se você autorizar/estiver autenticado.

Diga qual opção prefere que eu execute em seguida.
# inventario-server-auth-log
