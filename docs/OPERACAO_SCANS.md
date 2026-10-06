# Operação dos scans e API de gestão

## Configuração

O banco (SQLite local ou PostgreSQL) armazena fila, etapas e resultados. Não é necessário instalar um serviço de fila adicional. Redis continua sendo utilizado para rate limiting em produção.

Há dois modos:

- **Embutido:** `SCAN_WORKER_EMBUTIDO=1`. O servidor web inicia um consumidor que lança um processo Python por scan. É o padrão em desenvolvimento e está habilitado no `render.yaml`, que usa um worker Gunicorn.
- **Dedicado:** `SCAN_WORKER_EMBUTIDO=0` no servidor web. Inicie `python worker.py` em outro processo, na pasta `SecureScopeProject/securescope`, com o mesmo ambiente, código e banco. No Windows, a partir dessa pasta, use `..\..\.venv\Scripts\python.exe worker.py`.

O modo dedicado é indicado ao separar a capacidade de processamento do servidor web. Para SQLite, ambos os processos precisam apontar para o mesmo arquivo em `SQLITE_DATABASE_PATH`; para PostgreSQL, para a mesma `DATABASE_URL`. Não exponha o banco ou as credenciais no frontend.

Em produção sem o manifesto, configure explicitamente um dos modos. Se nenhum consumidor estiver executando, as tarefas permanecem **na_fila**, visíveis no histórico.

## Ciclo e recuperação

1. O upload é validado, limitado a 10 MB e persistido no banco; o painel recebe HTTP 202 com `scan_id`.
2. Um consumidor reserva a tarefa com atualização atômica. Dois consumidores não executam a mesma reserva.
3. O processo filho executa SAST, SCA ou DAST com as validações existentes do scanner.
4. Achados, vínculos, snapshots e status final são gravados na mesma transação. Uma falha de consolidação não publica resultados parciais.
5. O upload original é apagado da fila na conclusão ou falha. Snapshots e evidências permanecem disponíveis para consulta.

Cada conta pode manter até três scans na fila/em progresso. O processador limita cada execução a 30 minutos. Ao reiniciar, o consumidor continua os jobs ainda na fila. Reservas interrompidas há mais de 30 minutos são marcadas como erro, sem repetir automaticamente um scan ativo DAST. O usuário pode reenviar o alvo após revisar a falha. Tokens de reserva impedem uma execução antiga de publicar resultados após a recuperação.

As etapas e o campo `progresso` representam marcos do processamento, não uma estimativa de duração. O painel mostra a etapa e atualiza a lista periodicamente. Recarregar/fechar o navegador não cancela um scan.

## Migração e dados antigos

As migrações são aditivas e idempotentes. Faça backup antes da atualização. Scans antigos permanecem no histórico como legados; sem snapshots/tipo/alvo compatíveis, a comparação é recusada. Achados legados e manuais não são mesclados retroativamente.

Para SAST, a identidade inclui projeto, caminho relativo, regra e linha. Para SCA, inclui projeto, pacote e identificador da vulnerabilidade. Para DAST, inclui alvo, URL afetada, regra/título e parâmetro. A identidade é separada por conta. Uma redetecção preserva a avaliação e o status do registro e acrescenta auditoria e snapshot. Isso exige revisão do analista quando uma vulnerabilidade anteriormente corrigida reaparece.

## Rotas principais

Todas as rotas abaixo exigem autenticação por cookie. POST, PUT e DELETE também exigem o token CSRF em `X-CSRF-TOKEN`. Os controles de acesso são verificados no servidor.

| Método | Rota | Finalidade |
| --- | --- | --- |
| GET | `/gestao/vulnerabilidades` | Consulta pessoal ou de uma equipe, com filtros |
| GET | `/gestao/exportar/csv` ou `/gestao/exportar/json` | Exportação com os mesmos filtros |
| GET | `/gestao/vulnerabilidades/<id>` | Detalhes, membros elegíveis, comentários e auditoria |
| PUT | `/gestao/vulnerabilidades/<id>/status` | `status` e `justificativa` |
| PUT | `/gestao/vulnerabilidades/<id>/colaboracao` | `equipe_id` e/ou `responsavel_id`, ou `null` para remover |
| POST | `/gestao/vulnerabilidades/<id>/comentarios` | `texto` com até 2.000 caracteres |
| GET / POST | `/equipes` | Listar espaços acessíveis / criar equipe com `nome` |
| GET / POST | `/equipes/<id>/membros` | Consultar membros / cadastrar e-mail existente com papel |
| DELETE | `/equipes/<id>/membros/<usuario>` | Revogar acesso, restrito ao gestor |
| GET / PUT | `/preferencias/alertas` | Antecedência `dias`, entre 0 e 90 |
| GET | `/alertas` | Avisos de SLA, com leitura persistida |
| POST | `/alertas/<id>/ler` | Marcar o aviso atual como lido |
| GET | `/scans?pagina=1` | Histórico pessoal, 20 itens por página |
| GET | `/scans/<id>` | Estado e resultado do scan |
| GET | `/scans/comparar?antes=1&depois=2` | Comparar duas execuções compatíveis |

Filtros: `nome`, `ativo`, `origem`, `status`, `prioridade` (`critica`, `alta`, `media`, `baixa`) e `equipe_id`. Sem equipe, a consulta retorna apenas registros do usuário.

As rotas de scanner existentes continuam aceitando execução síncrona para compatibilidade. Para enfileirar, envie `segundo_plano=1` no formulário SCA/SAST ou `segundo_plano: true` no JSON DAST. O campo opcional `alvo` identifica o projeto de SCA/SAST. No DAST, a identidade do alvo é a URL validada.

## Validação

Na raiz do repositório, com as dependências instaladas:

```powershell
python -m unittest discover -s SecureScopeProject/tests -p "test_*.py"
node --check SecureScopeProject/securescope/script.js
node --check SecureScopeProject/securescope/gestao.js
```

A suíte de integração usa banco SQLite temporário e desabilita provedores de IA. Não altera os dados de uso do projeto. Valide também PostgreSQL e os serviços externos no ambiente de homologação antes de publicar esta versão.
