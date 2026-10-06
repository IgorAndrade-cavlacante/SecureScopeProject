# Funcionalidades implementadas no SecureScope

As nove propostas foram implementadas no código local. A publicação em um servidor existente exige implantar esta versão e configurar o processamento da fila. A apresentação anteriormente criada descreve a fase de propostas e não foi alterada nesta implementação.

| Funcionalidade | Onde usar | Comportamento |
| --- | --- | --- |
| Filtros combinados | Seção Vulnerabilidades | Nome, ativo, origem, status, faixa de prioridade e espaço pessoal/equipe |
| Exportação CSV/JSON | Botões abaixo dos filtros | Exporta a seleção com UTF-8; CSV neutraliza valores interpretáveis como fórmulas |
| Histórico de scans | Abaixo da tabela de vulnerabilidades | Paginação de 20 execuções, tipo, alvo, datas, etapa, falhas e resultado |
| Corrigir e reabrir | Botão Gerenciar de cada achado | Justificativa obrigatória, identidade do autor, data e atualização de SLA/KPIs |
| Detecção de duplicados | Automática ao finalizar scans | Vincula o achado a cada scan, sem duplicar o registro nem substituir decisões humanas |
| Comparação de scans | Histórico de scans | Exibe novos, persistentes e não detectados; exige mesmo tipo, alvo e modo |
| Responsáveis e comentários | Gerenciar e Equipes e permissões | Compartilhamento explícito por achado; gestor administra membros, analista trata, leitor consulta |
| Alertas de SLA | Seção Alertas de SLA | Antecedência de 0 a 90 dias; leitura persistente, alerta novo quando passa a violado |
| Scans em segundo plano | Área de scanners | Requisição retorna imediatamente; fila e resultados persistidos no banco |

## Regras de uso

- Informe um nome estável em **Projeto / alvo lógico** para comparar arquivos de um mesmo projeto. Sem esse nome, o alvo é o nome do arquivo. Para DAST, o alvo é a URL.
- A identificação SAST considera arquivo, regra e linha. Mover o código para outra linha pode criar um achado diferente. Para SCA, usa pacote e CVE/identificador OSV; para DAST, URL, regra/título e parâmetro.
- Um achado redetectado preserva o status e a avaliação já registrados. A evidência de cada nova execução fica no snapshot do scan e a recorrência aparece na auditoria. Reabra manualmente quando a revisão confirmar recorrência.
- Scans antigos sem snapshots continuam no histórico, mas não podem ser comparados. Não há fusão retroativa de registros antigos ou manuais.
- Ausência em um scan não comprova correção e não altera o status automaticamente.
- Reabrir conserva o prazo original de SLA. Corrigida e Isolada saem dos indicadores de achados pendentes.
- Os alertas são internos ao painel, sem envio de e-mails ou notificações externas.
- Compartilhar um achado inclui seus detalhes e histórico. Os demais dados da conta e os scans continuam privados.
- Remover um membro revoga seu acesso à equipe, limpa suas atribuições e torna privados os achados de propriedade desse membro que estavam compartilhados nesse espaço.
- PDF e indicadores gerais continuam referentes à conta pessoal; CSV/JSON seguem o espaço e os filtros selecionados.

## Operação e validação

Consulte [GUIA_DE_USO.md](GUIA_DE_USO.md) e [OPERACAO_SCANS.md](OPERACAO_SCANS.md). A suíte em `SecureScopeProject/tests` cobre autenticação, permissões, isolamento, exportação, transições, snapshots, concorrência, falhas e recuperação da fila. Os testes de banco desta entrega usam SQLite; PostgreSQL precisa de validação no ambiente de homologação antes da publicação.
