# Politica de seguranca do SecureScope

## Segredos e configuracao

- Segredos reais devem existir somente no gerenciador de segredos do deploy ou no `.env` local ignorado pelo Git.
- O repositorio deve conter apenas `.env.example` com valores ficticios.
- Em producao, `APP_ENV=production` e obrigatorio. A aplicacao nao inicia sem `JWT_SECRET_KEY`, `ALLOWED_ORIGINS`, `DATABASE_URL` e um `RATELIMIT_STORAGE_URI` compartilhado.
- Toda chave publicada, enviada por chat ou registrada em log deve ser revogada e substituida.

## Autenticacao

- O cadastro publico fica desabilitado por padrao em producao.
- Contas criadas pelo cadastro publico recebem sempre o papel `analista`.
- Senhas devem ter de 12 a 128 caracteres, com letras maiusculas, minusculas e numeros.
- O JWT e armazenado em cookie `HttpOnly`, com `SameSite=Strict`, expiracao curta e protecao CSRF.
- Endpoints de login e cadastro possuem limites por IP; login tambem possui limite por conta anonimizada.

## Banco de dados

- Producao deve usar PostgreSQL com TLS e um usuario exclusivo da aplicacao.
- O usuario da aplicacao deve possuir somente `SELECT`, `INSERT`, `UPDATE` e `DELETE` nas tabelas necessarias. Ele nao deve ser superusuario, dono do banco ou possuir permissao para criar roles.
- Migracoes devem ser executadas por uma credencial separada e temporaria.
- Toda consulta com dados de clientes deve filtrar por `usuario_id`; consultas devem permanecer parametrizadas.
- O fallback para SQLite e permitido somente em desenvolvimento. As chaves estrangeiras do SQLite ficam habilitadas.
- RLS do PostgreSQL/Supabase deve ser implantado antes de acesso direto ao banco por clientes. A API atual usa conexao de backend e mantem o isolamento na camada da aplicacao.
- Backups devem ser criptografados, ter acesso restrito e passar por teste periodico de restauracao.

## Rate limiting e monitoramento

- Producao deve usar Redis ou storage equivalente para compartilhar contadores entre instancias.
- Respostas `429`, falhas de login, erros de autorizacao e eventos administrativos devem ser monitorados.
- Logs nao devem conter senhas, JWTs, chaves de API, strings completas de conexao ou respostas brutas de provedores.

## Resposta a exposicao de segredo

1. Revogar o segredo no provedor.
2. Criar uma nova credencial com o menor privilegio possivel.
3. Atualizar o gerenciador de segredos do deploy.
4. Verificar logs, branches, tags, pull requests, Actions, releases e artefatos.
5. Limpar o historico Git quando necessario e solicitar novo clone para a equipe.
6. Registrar data, impacto e acao corretiva sem copiar o valor exposto.
