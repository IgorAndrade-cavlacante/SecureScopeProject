# SecureScope ASPM — Setup Local com Postgres (Supabase)

## 📋 Pré-requisitos

1. **Supabase Account** (gratuita em https://supabase.com)
2. **Python 3.9+** instalado
3. **pip** (gestor de pacotes Python)

---

## 🚀 Passo 1: Criar projeto no Supabase

1. Acesse https://supabase.com e faça login ou crie uma conta.
2. Clique em "New Project" e preencha:
   - **Name:** `securescope` (ou qualquer nome)
   - **Database Password:** gere uma senha forte
   - **Region:** escolha a mais próxima de você
3. Clique "Create new project" e aguarde ~2 minutos.
4. Quando estiver pronto, vá a **Settings > Database** na sidebar.
5. Procure pela seção "Connection string" e copie o URI (modo "Session pooler" é recomendado):
   ```
   postgresql://postgres:SENHA_AQUI@db.seu-projeto.supabase.co:5432/postgres
   ```

---

## 🔧 Passo 2: Configurar ambiente local

1. **Descompacte o arquivo `SecureScope_Postgres_MultiTenant.zip`** na pasta onde quer rodar.
2. **Entre na pasta:**
   ```bash
   cd SecureScopeProject-main/securescope
   ```
3. **Copie o arquivo de exemplo:**
   ```bash
   cp .env.example .env
   ```
4. **Abra `.env` em um editor de texto e preencha:**
   ```
   DATABASE_URL=postgresql://postgres:SENHA_AQUI@db.seu-projeto.supabase.co:5432/postgres
   JWT_SECRET_KEY=gere-um-valor-aleatorio-forte
   # ALLOWED_ORIGINS=https://seudominio.com (deixe comentado para desenvolvimento local)
   ```
   
   Para gerar uma chave JWT aleatória, rode no terminal:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

---

## 📦 Passo 3: Instalar dependências

```bash
pip install -r requirements.txt
```

(Se der erro de permissão no Linux/Mac, tente `pip install --user -r requirements.txt` ou use `sudo`.)

---

## ▶️ Passo 4: Rodar o servidor

```bash
python3 app.py
```

Você deve ver algo como:
```
[migração] Coluna 'usuario_id' adicionada em vulnerabilidades.
[migração] Coluna 'ip_origem' adicionada em historico.
...
Iniciando a API SecureScope com IA...
 * Running on http://127.0.0.1:5000
```

---

## 🌐 Passo 5: Acessar a aplicação

1. Abra o navegador em **http://localhost:5000**
2. Clique no botão de autenticação no canto superior direito.
3. **Crie uma conta** (e-mail, senha, nome).
4. **Faça login** com essas credenciais.
5. Pronto! Agora você pode:
   - Registrar vulnerabilidades.
   - Ver insights da IA.
   - Gerar relatórios em PDF.
   - Consultar status de SLA e KPIs de governança.

---

## 🔒 Isolamento por usuário (multi-tenant)

Cada usuário só vê suas próprias vulnerabilidades. Para testar:

1. **Usuário A:** 
   - Crie uma conta (ex: `alice@test.com`)
   - Faça login e registre 2 vulnerabilidades.
   - Veja a tabela com 2 entradas.

2. **Usuário B:**
   - Clique em "Sair" (logout).
   - Crie outra conta (ex: `bob@test.com`).
   - Faça login e veja a tabela vazia — suas vuln. não aparecem!
   - Registre 1 vulnerabilidade. Vê só a sua.

3. **Volte para Usuário A:**
   - Logout e login novamente com `alice@test.com`.
   - As 2 vulnerabilidades dela estão lá; as do Bob não aparecem.

---

## 🐛 Troubleshooting

### "ModuleNotFoundError: No module named 'psycopg2'"
Rode: `pip install psycopg2-binary`

### "ERRO: DATABASE_URL não configurada"
Verifique se o arquivo `.env` existe e tem `DATABASE_URL=...` preenchido.

### "Connection refused (Postgres)"
- Verifique se a `DATABASE_URL` está correta.
- Confirme que copiou a string direto do painel do Supabase.
- Tente conectar via terminal (ex: `psql DATABASE_URL`) pra testar.

### "Rota retorna 401 Unauthorized"
Verifique se você está logado (localStorage tem `ss_token`). Algumas rotas agora exigem autenticação.

---

## 📌 Notas Importantes

- **SQLite foi removido.** Agora usa Postgres/Supabase exclusivamente.
- **Dados antigos (SQLite):** Se você tinha dados em `vulnerabilidades.db`, eles **não migraram automaticamente** — você precisaria exportá-los manualmente se for crítico.
- **Multi-tenant ativo:** Cada usuário tem isolamento total de dados via `usuario_id`. Nem admins conseguem ver dados de outros usuários (por design do Ponto 3).
- **Senhas:** Armazenadas com hash bcrypt seguro via `werkzeug.security`.

---

## 📚 Próximas etapas

Veja o arquivo `plano_multitenant_e_deploy.md` para:
- Opção A vs B do Supabase (se quiser evoluir para RLS).
- Plano de deploy (Ponto 4) em produção (Render + Vercel).
- Checklist final antes da apresentação.

---

## ✅ Checklist de Teste Local

- [ ] App sobe sem erro em http://localhost:5000
- [ ] Consegue registrar uma conta nova
- [ ] Consegue fazer login com essas credenciais
- [ ] Tabela de vulnerabilidades carrega (vazia no começo)
- [ ] Consegue adicionar uma vulnerabilidade
- [ ] Consegue validá-la e acionar Circuit Breaker
- [ ] Insights da IA aparecem (se houver histórico)
- [ ] Consegue gerar PDF do relatório
- [ ] Logout e login com outra conta — dados isolados ✓
- [ ] Swagger/API disponível em http://localhost:5000/docs (se implementado)

Boa sorte! 🎯
