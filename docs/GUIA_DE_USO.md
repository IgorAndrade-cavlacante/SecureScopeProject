# Guia de instalação e uso do SecureScope

## 1. Requisitos

- Python 3.11 ou 3.12 como versões sugeridas para o ambiente local, com `pip` e `venv`.
- Navegador atualizado.
- Internet para instalar dependências, consultar a OSV, usar provedores de IA e carregar recursos externos da interface/PDF.
- PostgreSQL e Redis para a configuração de produção. A demonstração local abaixo usa SQLite.

Execute os comandos no PowerShell. Comece na pasta raiz do repositório, que contém `SecureScopeProject`, `scanner-test-files` e este README.

## 2. Instalar dependências

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\SecureScopeProject\securescope\requirements.txt
```

O caminho explícito do Python dispensa ativar o ambiente virtual. Não é necessário instalar Node.js nem executar os arquivos HTML separadamente.

## 3. Configurar o ambiente local

Se ainda não existir um `.env`, copie o exemplo:

```powershell
Copy-Item .\SecureScopeProject\securescope\.env.example .\SecureScopeProject\securescope\.env
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
```

Edite `SecureScopeProject/securescope/.env`. Use a chave gerada no lugar de `COLE_A_CHAVE_GERADA` e ajuste as variáveis abaixo, sem duplicá-las:

```dotenv
APP_ENV=development
USE_SQLITE=1
JWT_SECRET_KEY=COLE_A_CHAVE_GERADA
RATELIMIT_STORAGE_URI=memory://
GEMINI_API_KEY=
GROQ_API_KEY=
```

Com `USE_SQLITE=1`, a conexão PostgreSQL do exemplo não será usada. As tabelas são preparadas na inicialização. O arquivo SQLite padrão fica em `SecureScopeProject/securescope/securescope.db`; preserve-o para manter os registros entre execuções.

Deixe as chaves de IA vazias para começar sem provedores externos. Para habilitar a triagem, informe suas próprias chaves Gemini e/ou Groq. Nesse modo, informações dos achados são enviadas aos provedores configurados. Sem provedores, a triagem opera em modo degradado e mantém os achados para revisão.

Não publique o `.env`, chaves ou banco de dados no repositório.

## 4. Iniciar e acessar

```powershell
Set-Location .\SecureScopeProject\securescope
..\..\.venv\Scripts\python.exe app.py
```

Mantenha o terminal aberto. Acesse:

- Página inicial: `http://127.0.0.1:5000/`
- Painel: `http://127.0.0.1:5000/painel`

Use o mesmo endereço durante a sessão, sem alternar entre `localhost` e `127.0.0.1`. Para encerrar, pressione `Ctrl+C` no terminal.

## 5. Criar conta e entrar

1. No painel, clique em **Entrar** e depois em **Criar Conta**.
2. Preencha os campos apresentados com seu nome, e-mail e senha.
3. Use uma senha de 12 a 128 caracteres, incluindo maiúscula, minúscula e número.
4. Conclua o cadastro e entre com e-mail e senha.

Cada conta acessa seus próprios registros. O cadastro público é habilitado por padrão em desenvolvimento e desabilitado por padrão em produção.

## 6. Cadastrar uma vulnerabilidade manualmente

1. Clique em **Nova Vulnerabilidade**.
2. Informe o **Nome da Ameaça** e o **Ativo/Sistema Afetado**.
3. Preencha impacto, frequência e gravidade, de 0 a 100. Caso apareça uma sugestão, revise antes de aceitar os valores.
4. Informe os dados opcionais de CVE/CVSS/EPSS quando conhecidos. CVSS usa a escala de 0 a 10.
5. Responda às perguntas de contexto exibidas e envie o formulário.
6. Confira o registro, o risco e a prioridade na tabela.

## 7. Executar SAST: código Python

1. Na área de scanners, selecione **SAST**.
2. Selecione um arquivo `.py` ou um `.zip` contendo código Python.
3. Para uma demonstração, use `scanner-test-files/codigo_sast_vulneravel.py`, a partir da raiz do projeto. Não execute essa amostra; ela contém padrões inseguros deliberados.
4. Informe um nome estável no campo **Projeto / alvo lógico**, clique em **Iniciar Scan SAST** e acompanhe o **Histórico de scans** abaixo da tabela.
5. Clique em **Ver resultado** no histórico e use **Analisar** na tabela para consultar os detalhes disponíveis, como arquivo, linha e regra.

O Bandit analisa o código sem executá-lo. Há limite de 10 MB por arquivo Python e de 15 MB por requisição HTTP, incluindo o upload. O ZIP deve conter até 200 arquivos Python e até 50 MB descompactados. Os caminhos das subpastas são preservados.

## 8. Executar SCA: dependências Python

1. Selecione **SCA**.
2. Envie um `.txt` com dependências e versões, preferencialmente fixadas no formato `pacote==versao`.
3. Para demonstrar, use `scanner-test-files/requirements_sca_vulneravel.txt`. Envie esse arquivo ao scanner; não instale suas dependências vulneráveis no ambiente da ferramenta.
4. Preencha **Projeto / alvo lógico**, clique em **Iniciar Scan SCA** e acompanhe no **Histórico de scans**.
5. Consulte os achados e as referências disponíveis, incluindo pacote, versão e correção quando informada pela fonte.

O scanner consulta a OSV e aceita até 100 pacotes por análise. A quantidade de achados depende da base consultada e da triagem. Ausência de resultados não comprova ausência de vulnerabilidades.

## 9. Executar DAST: aplicação web

Use uma aplicação própria ou um alvo para o qual você tenha autorização de teste.

1. Selecione **DAST**.
2. Informe a URL completa, com `http://` ou `https://`.
3. Clique em **Iniciar Scan DAST** e acompanhe a execução em segundo plano no **Histórico de scans**.
4. Verifique o modo informado: com OWASP ZAP disponível, o scanner pode executar exploração de páginas e análise ativa; sem o daemon, há uma alternativa de análise passiva HTTP.

O modo passivo tem cobertura mais limitada. Para integrar um daemon ZAP já configurado, defina `ZAP_API_URL` e `ZAP_API_KEY` no `.env` e reinicie o SecureScope.

### Demonstração local controlada

1. Acrescente `DAST_PERMITIR_REDE_INTERNA=true` ao `.env` somente no ambiente local e reinicie o SecureScope.
2. Abra outro PowerShell na raiz do repositório e execute:

   ```powershell
   .\.venv\Scripts\python.exe .\scanner-test-files\demo_dast_alvo.py
   ```

3. No painel, analise `http://127.0.0.1:5055/`.
4. Ao terminar, encerre o alvo com `Ctrl+C`, remova a liberação de rede interna e reinicie o SecureScope.

Por padrão, o scanner bloqueia alvos de rede interna. Não habilite essa exceção no ambiente público de produção.

## 10. Revisar resultados e gerar relatório

1. Consulte a tabela e os indicadores de risco/SLA.
2. Clique em **Analisar** para revisar a explicação e as evidências disponíveis.
3. Use **Validar** após revisar o achado; isso registra o status de validado, sem significar que a vulnerabilidade foi corrigida.
4. A ação **Circuit Breaker** registra o status de isolamento no sistema. Ela não implementa bloqueio real de rede nem altera a aplicação analisada.
5. Clique em **Gerar Relatório PDF** e salve o arquivo gerado pelo navegador.
6. Ao terminar, use **Sair** no menu da conta.

Os achados e as sugestões de IA precisam de revisão humana antes de orientar correções.

## 11. Problemas comuns

| Sintoma | Como proceder |
| --- | --- |
| Python não encontrado | Confira a instalação e o PATH; em instalações com o launcher, use `py` para criar o ambiente virtual |
| Módulo não encontrado | Instale os requisitos usando o Python de `.venv` e inicie com esse mesmo executável |
| Falha de banco na demonstração | Confirme `APP_ENV=development` e `USE_SQLITE=1` no `.env` e reinicie |
| Sessão expirada ou erro 401 | Entre novamente; a duração padrão é de 60 minutos |
| Cadastro desabilitado | O administrador precisa configurar `ALLOW_PUBLIC_REGISTRATION` para permitir cadastro |
| Erro 429 | Aguarde o limite de requisições; há limites específicos para login e scanners |
| Upload rejeitado | Verifique a extensão e os limites de tamanho; divida arquivos grandes |
| SCA não conclui | Confira acesso à internet/OSV e o formato das dependências |
| Alvo DAST bloqueado | Confira a URL e a política de rede; para a demonstração local, siga a seção 9 |
| IA apresenta erro | Remova valores de exemplo das chaves; use chaves válidas ou deixe-as vazias |
| PDF não é gerado | Confira acesso aos recursos externos carregados pelo navegador e os erros no console |

## 12. Produção e manutenção

O arquivo `render.yaml` contém a configuração de implantação existente. Em produção, configure `APP_ENV=production`, `DATABASE_URL`, `JWT_SECRET_KEY` com pelo menos 32 caracteres, `ALLOWED_ORIGINS` com a origem real e `RATELIMIT_STORAGE_URI` com armazenamento compartilhado, como Redis. Use HTTPS e um servidor WSGI. O Gunicorn do manifesto é destinado a ambientes compatíveis, como Linux.

Faça backup do banco antes de atualizar a aplicação: a inicialização pode aplicar migrações. Para executar a suíte existente, a partir da raiz, com dependências instaladas:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s .\SecureScopeProject\tests -p "test_*.py"
```

## 13. Grupo e licença

Preencha os nomes e contribuições em [INTEGRANTES.md](../INTEGRANTES.md). A licença adotada é [BSD-3-Clause](../LICENSE).


## 14. Filtrar e exportar

1. Na seção **Vulnerabilidades**, escolha **Meus achados** ou uma equipe da qual participa.
2. Combine nome, ativo, origem, status e prioridade; clique em **Aplicar filtros**.
3. Confira a quantidade de resultados. **Limpar** restaura a consulta pessoal sem filtros.
4. Clique em **Exportar CSV** ou **Exportar JSON** para baixar a seleção atual. O CSV usa ponto e vírgula e UTF-8, com proteção contra fórmulas.

## 15. Corrigir, reabrir e comentar

1. Clique em **Gerenciar** na linha do achado.
2. Escolha **Corrigida**, descreva a justificativa e salve. A data e o responsável pela alteração ficam na auditoria.
3. Para uma recorrência confirmada, selecione **Reabrir** e explique o motivo. O prazo original de SLA é mantido.
4. Use **Comentário** para registrar evidências textuais e decisões. Consulte **Histórico de alterações** no mesmo diálogo.
5. Use **Responsável** para atribuir o tratamento a você ou a um membro com permissão de escrita da equipe.

## 16. Criar equipes e compartilhar

1. Abra **Equipes e permissões**, abaixo da tabela, e crie uma equipe.
2. Selecione a equipe e adicione o e-mail de uma conta já cadastrada. O criador é o gestor; os novos membros podem ser **Analista** ou **Leitor**.
3. Em **Gerenciar** um achado seu, escolha a equipe em **Compartilhar com uma equipe** e salve. O achado e seu histórico ficam acessíveis aos membros; o restante da conta continua privado.
4. Membros podem consultar os achados pelo filtro **Espaço**. Analistas também podem comentar e alterar o tratamento; leitores apenas consultam.
5. Para revogar um acesso, o gestor usa **Remover acesso**. Para encerrar o compartilhamento de um achado, seu dono seleciona **Privado**.

Não são enviados convites por e-mail. Adicionar/alterar um membro exige uma conta existente. O dono de um achado preserva acesso aos próprios registros.

## 17. Histórico, deduplicação e comparação

1. Acompanhe **Histórico de scans**; a atualização ocorre automaticamente. Você pode navegar pelas páginas e abrir **Ver resultado** após a conclusão.
2. Achados repetidos são associados ao registro existente e contabilizados como já registrados. Cada scan preserva sua evidência e prioridade calculada, sem sobrescrever decisões humanas anteriores.
3. Clique em **Usar como anterior** e **Usar como posterior** em duas execuções concluídas. É possível selecionar IDs de páginas diferentes.
4. Clique em **Comparar**. Os scans devem ter o mesmo tipo, projeto/alvo e modo de análise. ZAP ativo e HTTP passivo não são comparáveis entre si.
5. Revise novos, persistentes e não detectados novamente. A comparação não fecha vulnerabilidades automaticamente.

## 18. Alertas internos de SLA

1. Abra **Alertas de SLA**.
2. Defina a antecedência entre 0 e 90 dias e clique em **Salvar preferência**.
3. Use **Gerenciar** para tratar um achado ou **Marcar como lido** para retirar o aviso da lista de não lidos.
4. Um aviso lido em risco reaparece como novo se o prazo for violado. Achados corrigidos ou isolados deixam de gerar alertas pendentes.

Os alertas abrangem achados pessoais e compartilhados com suas equipes. Não há envio externo de mensagens.

## 19. Execução em segundo plano

O painel envia o scan e libera a tela. Em desenvolvimento, um processador embutido inicia automaticamente e executa os scans em processos separados. O histórico persiste no mesmo banco da aplicação e pode ser consultado após recarregar a página.

Há limite de três scans pendentes por conta e tempo máximo de 30 minutos por execução em segundo plano. O conteúdo original enviado é removido da fila ao terminar ou falhar; as evidências dos achados continuam no banco. Faça backup antes de atualizar o servidor, pois novas tabelas e colunas são criadas na inicialização.

O `render.yaml` habilita o processamento embutido. Para executar um worker dedicado, escalar ou investigar uma fila parada, siga [Operação dos scans](OPERACAO_SCANS.md).
