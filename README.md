# SecureScope

Ferramenta web para registrar, analisar e priorizar vulnerabilidades de segurança, com backend Flask e interface em HTML, CSS e JavaScript.

## Documentação

- [Passo a passo de instalação e uso](docs/GUIA_DE_USO.md)
- [Integrantes do grupo — preencher aqui](INTEGRANTES.md)
- [Licença BSD de 3 cláusulas](LICENSE.MD)

## Funcionalidades atuais

- Cadastro e autenticação de usuários.
- Cadastro manual de vulnerabilidades e avaliação de contexto.
- SAST: análise de código Python com Bandit, recebendo `.py` ou `.zip`.
- SCA: consulta de dependências Python à base OSV a partir de um arquivo `.txt`.
- DAST: integração com OWASP ZAP e alternativa de análise passiva HTTP.
- Priorização de risco, acompanhamento de SLA e análise de achados.
- Triagem opcional com Gemini e Groq.
- Geração de relatório PDF.
- Filtros combinados e exportação CSV/JSON dos resultados filtrados.
- Histórico paginado e comparação de scans com snapshots de cada execução.
- Detecção de achados repetidos por conta, projeto, regra e localização.
- Correção e reabertura com justificativa, auditoria e atualização de SLA.
- Equipes com gestor, analistas e leitores; responsáveis e comentários.
- Alertas internos de SLA com antecedência configurável e leitura persistida.
- Fila de scans persistente, executada em processos separados com limite de tempo.

## Começar

Siga o [guia de uso](docs/GUIA_DE_USO.md). Para desenvolvimento local, é possível usar SQLite e executar sem chaves de IA. O frontend é servido pelo próprio Flask; abra `http://127.0.0.1:5000/painel` após iniciar o backend.

## Estrutura

| Caminho | Conteúdo |
| --- | --- |
| `SecureScopeProject/securescope/` | Backend, painel, scanners e configuração de exemplo |
| `SecureScopeProject/Home/` | Página inicial |
| `SecureScopeProject/tests/` | Testes de segurança e regressão |
| `scanner-test-files/` | Amostras para demonstração |
| `docs/` | Guia de uso, funcionalidades e operação da fila |
| `INTEGRANTES.md` | Identificação e contribuições do grupo |

## Licença

O código original deste projeto é disponibilizado sob **BSD-3-Clause**, conforme o arquivo [LICENSE.MD](LICENSE.MD), usando o [texto de referência da Open Source Initiative](https://opensource.org/license/bsd-3-clause). Dependências e materiais de terceiros permanecem sujeitos às respectivas licenças.
