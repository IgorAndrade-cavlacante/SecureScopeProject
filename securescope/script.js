const API_URL = 'http://127.0.0.1:5000';

let endpointAtual = '/vulnerabilidades';
let debounceSugestaoTimer = null;
let sugestaoAtual = null;

// Estado do wizard interativo da IA
let categoriaWizardAtual = null;
let perguntasWizard = [];
let indiceWizard = 0;
let respostasWizard = {};

window.onload = () => {
    carregarVulnerabilidades();
    carregarInsightsIA();
    carregarOrigens();
};

function mostrarToast(msg, cor = '#2c3e50') {
    const toast = document.getElementById('toast');

    toast.textContent = msg;
    toast.style.background = cor;
    toast.style.display = 'block';

    setTimeout(() => {
        toast.style.display = 'none';
    }, 3000);
}

async function carregarVulnerabilidades(endpoint = '/vulnerabilidades') {

    endpointAtual = endpoint;

    const response = await fetch(`${API_URL}${endpoint}`);

    const dados = await response.json();

    renderizarTabela(dados);
}

function renderizarTabela(dados) {

    const tbody = document.getElementById('tabelaCorpo');

    tbody.innerHTML = '';

    if (dados.length === 0) {

        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="tabela-vazia">
                    Nenhuma vulnerabilidade registrada ainda.
                </td>
            </tr>
        `;

        return;
    }

    dados.forEach(vuln => {

        const tr = document.createElement('tr');

        const score = parseFloat(vuln.score);
        const prioridade = parseFloat(vuln.prioridade ?? vuln.score);

        if (score > 80) {
            tr.classList.add('risco-critico');
        }

        let classePrioridade = '';
        if (prioridade >= 90) {
            classePrioridade = 'prioridade-alta';
        } else if (prioridade >= 75) {
            classePrioridade = 'prioridade-media';
        }

        tr.innerHTML = `
            <td>${vuln.nome}</td>
            <td>${vuln.ativo || '—'}</td>
            <td>${vuln.impacto}</td>
            <td>${vuln.frequencia}</td>
            <td>${vuln.gravidade}</td>
            <td><strong>${score.toFixed(2)}</strong></td>
            <td class="${classePrioridade}"><strong>${prioridade.toFixed(1)}</strong></td>
            <td>${vuln.status}</td>
            <td>
                <button class="btn-validar"
                    onclick="validarVuln(${vuln.id})">
                    Validar
                </button>

                <button class="btn-circuit"
                    onclick="acionarCircuitBreaker(${vuln.id})">
                    Circuit Breaker
                </button>

                <button class="btn-analisar"
                    onclick="abrirAnaliseIA(${vuln.id})">
                    🔍 Analisar
                </button>
            </td>
        `;

        tbody.appendChild(tr);
    });
}

document.getElementById('formVuln').addEventListener('submit', async (e) => {

    e.preventDefault();

    const payload = {
        nome: document.getElementById('nome').value,
        impacto: parseFloat(document.getElementById('impacto').value),
        frequencia: parseFloat(document.getElementById('frequencia').value),
        gravidade: parseFloat(document.getElementById('gravidade').value),
        ativo: document.getElementById('ativo').value,
        origem: document.getElementById('origem').value,
        exposta_internet: respostasWizard.exposta_internet || false,
        exploit_publico: respostasWizard.exploit_publico || false,
        dados_sensiveis: respostasWizard.dados_sensiveis || false,
        escalonamento_privilegio: respostasWizard.escalonamento_privilegio || false,
        ambiente_producao: respostasWizard.ambiente_producao || false
    };

    const res = await fetch(`${API_URL}/vulnerabilidades`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    });

    const data = await res.json();

    mostrarToast(
        `✅ "${payload.nome}" adicionada! Risk Index™: ${data['Risk Index™']} | Prioridade: ${data.prioridade}`,
        '#28a745'
    );

    document.getElementById('formVuln').reset();
    esconderSugestaoIA();
    esconderWizard();

    carregarVulnerabilidades();
});

// ─────────────────────────────────────────────
// SUGESTÃO IA (autocomplete de Impacto/Frequência/Gravidade)
// ─────────────────────────────────────────────

document.getElementById('nome').addEventListener('input', (e) => {

    const nome = e.target.value.trim();

    clearTimeout(debounceSugestaoTimer);

    if (nome.length < 3) {
        esconderSugestaoIA();
        esconderWizard();
        return;
    }

    debounceSugestaoTimer = setTimeout(() => buscarSugestaoIA(nome), 500);
});

async function buscarSugestaoIA(nome) {

    try {
        const res = await fetch(`${API_URL}/ia/sugerir`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ nome })
        });

        const sugestao = await res.json();

        if (!sugestao || sugestao.categoria === 'Geral/Desconhecida') {
            esconderSugestaoIA();
            esconderWizard();
            return;
        }

        sugestaoAtual = sugestao;

        document.getElementById('ia-categoria-texto').innerText =
            `Categoria detectada: ${sugestao.categoria} (Risk Index™ sugerido: ${sugestao.risk_index_sugerido})`;

        document.getElementById('ia-sugestao').style.display = 'flex';

        if (sugestao.perguntas && sugestao.perguntas.length > 0) {
            iniciarWizard(sugestao.categoria, sugestao.perguntas);
        }

    } catch (error) {
        esconderSugestaoIA();
        esconderWizard();
    }
}

function esconderSugestaoIA() {
    sugestaoAtual = null;
    document.getElementById('ia-sugestao').style.display = 'none';
}

// ─────────────────────────────────────────────
// WIZARD INTERATIVO DA IA (perguntas de contexto)
// ─────────────────────────────────────────────

function iniciarWizard(categoria, perguntas) {
    // Se já está rodando o wizard pra essa mesma categoria, não reseta
    // as respostas que o analista já deu enquanto ele ainda está digitando.
    if (categoria === categoriaWizardAtual) return;

    categoriaWizardAtual = categoria;
    perguntasWizard = perguntas;
    indiceWizard = 0;
    respostasWizard = {};

    document.getElementById('ia-wizard').style.display = 'block';
    mostrarPerguntaWizard();
}

function mostrarPerguntaWizard() {
    const areaPergunta = document.getElementById('wizard-pergunta-area');
    const areaResumo = document.getElementById('wizard-resumo');

    if (indiceWizard >= perguntasWizard.length) {
        const ativos = Object.values(respostasWizard).filter(Boolean).length;
        areaPergunta.style.display = 'none';
        areaResumo.style.display = 'block';
        document.getElementById('wizard-resumo-texto').innerText =
            `✅ Análise de contexto concluída — ${ativos} de ${perguntasWizard.length} riscos ativos detectados.`;
        return;
    }

    const atual = perguntasWizard[indiceWizard];
    document.getElementById('wizard-progresso').innerText =
        `Pergunta ${indiceWizard + 1} de ${perguntasWizard.length}`;
    document.getElementById('wizard-pergunta').innerText = atual.pergunta;

    areaPergunta.style.display = 'block';
    areaResumo.style.display = 'none';
}

function responderWizard(resposta) {
    const atual = perguntasWizard[indiceWizard];
    if (!atual) return;

    respostasWizard[atual.chave] = resposta;
    indiceWizard++;
    mostrarPerguntaWizard();
}

function pularWizard() {
    for (let i = indiceWizard; i < perguntasWizard.length; i++) {
        respostasWizard[perguntasWizard[i].chave] = false;
    }
    indiceWizard = perguntasWizard.length;
    mostrarPerguntaWizard();
}

function refazerWizard() {
    indiceWizard = 0;
    respostasWizard = {};
    mostrarPerguntaWizard();
}

function esconderWizard() {
    categoriaWizardAtual = null;
    perguntasWizard = [];
    indiceWizard = 0;
    respostasWizard = {};
    document.getElementById('ia-wizard').style.display = 'none';
}

document.getElementById('wizard-sim').addEventListener('click', () => responderWizard(true));
document.getElementById('wizard-nao').addEventListener('click', () => responderWizard(false));
document.getElementById('wizard-pular').addEventListener('click', pularWizard);
document.getElementById('wizard-refazer').addEventListener('click', refazerWizard);

document.getElementById('btn-aceitar-ia').addEventListener('click', () => {

    if (!sugestaoAtual) return;

    document.getElementById('impacto').value = sugestaoAtual.impacto;
    document.getElementById('frequencia').value = sugestaoAtual.frequencia;
    document.getElementById('gravidade').value = sugestaoAtual.gravidade;

    esconderSugestaoIA();
});

document.getElementById('btn-editar-ia').addEventListener('click', () => {
    esconderSugestaoIA();
    document.getElementById('impacto').focus();
});

async function validarVuln(id) {

    await fetch(`${API_URL}/vulnerabilidades/${id}/validar`, {
        method: 'PUT'
    });

    mostrarToast(
        `✅ Vulnerabilidade #${id} validada!`,
        '#28a745'
    );

    carregarVulnerabilidades();
}

async function acionarCircuitBreaker(id) {

    const confirmar = confirm(
        "ALERTA CRÍTICO: deseja isolar esta ameaça?"
    );

    if (!confirmar) return;

    await fetch(`${API_URL}/circuit-breaker/${id}`, {
        method: 'POST'
    });

    mostrarToast(
        `🚨 Circuit Breaker acionado!`,
        '#dc3545'
    );

    carregarVulnerabilidades();
}

async function carregarInsightsIA() {

    try {

        const res = await fetch(`${API_URL}/ia/insights`);

        const dados = await res.json();

        if (dados.status === 'sucesso') {

            document.getElementById('ia-loading').style.display = 'none';

            document.getElementById('ia-stats-content').style.display = 'flex';

            document.getElementById('ia-total').innerText = dados.total_analisado;

            document.getElementById('ia-risco-medio').innerText =
                dados.risco_medio_geral;

            document.getElementById('ia-pior-risco').innerText =
                dados.pior_risco;

            document.getElementById('ia-melhor-risco').innerText =
                dados.melhor_risco;

            document.getElementById('ia-media-imp').innerText =
                dados.media_impacto;

            document.getElementById('ia-media-freq').innerText =
                dados.media_frequencia;

            document.getElementById('ia-media-grav').innerText =
                dados.media_gravidade;

        } else {
            document.getElementById('ia-loading').innerText =
                dados.mensagem || 'Histórico insuficiente para insights da IA.';
        }

        // Achados por origem e alertas de monitoramento funcionam mesmo
        // sem histórico validado — não dependem do "if sucesso" acima.

        if (dados.achados_por_origem && Object.keys(dados.achados_por_origem).length > 0) {
            document.getElementById('ia-origens-box').style.display = 'block';
            document.getElementById('ia-origens-lista').innerText =
                Object.entries(dados.achados_por_origem)
                    .map(([origem, total]) => `${origem}: ${total}`)
                    .join(' | ');
        }

        if (dados.alertas_monitoramento && dados.alertas_monitoramento.length > 0) {
            const painel = document.getElementById('ia-monitoramento');
            const lista = document.getElementById('ia-alertas-lista');

            lista.innerHTML = '';
            dados.alertas_monitoramento.forEach(msg => {
                const li = document.createElement('li');
                li.innerText = msg;
                lista.appendChild(li);
            });

            painel.style.display = 'block';
        }

    } catch (error) {

        document.getElementById('ia-loading').innerText =
            'Erro ao conectar com IA.';
    }
}

async function carregarOrigens() {
    try {
        const res = await fetch(`${API_URL}/ia/origens`);
        const origens = await res.json();

        const select = document.getElementById('origem');
        select.innerHTML = '';

        origens.forEach(origem => {
            const option = document.createElement('option');
            option.value = origem;
            option.innerText = origem;
            select.appendChild(option);
        });

    } catch (error) {
        // Mantém a opção padrão "Manual/Pentest" já presente no HTML.
    }
}

function voltarPadrao() {
    carregarVulnerabilidades('/vulnerabilidades');
}

// ─────────────────────────────────────────────
// RELATÓRIO EM PDF
// ─────────────────────────────────────────────

async function gerarRelatorio() {

    try {
        const res = await fetch(`${API_URL}/relatorio`);
        const dados = await res.json();

        if (!dados || dados.length === 0) {
            mostrarToast('⚠️ Nenhuma vulnerabilidade para gerar relatório.', '#e0a800');
            return;
        }

        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        const dataGeracao = new Date().toLocaleString('pt-BR');

        doc.setFontSize(16);
        doc.text('SecureScope — Relatório de Governança de Risco', 14, 18);

        doc.setFontSize(10);
        doc.text(`Gerado em: ${dataGeracao}`, 14, 25);

        const linhas = dados.map(vuln => [
            vuln.nome,
            vuln.impacto,
            vuln.frequencia,
            vuln.gravidade,
            parseFloat(vuln.score).toFixed(2),
            vuln.status
        ]);

        doc.autoTable({
            startY: 32,
            head: [['Nome', 'Impacto', 'Frequência', 'Gravidade', 'Risk Index™', 'Status']],
            body: linhas,
            headStyles: { fillColor: [44, 62, 80] },
            styles: { fontSize: 9 }
        });

        const nomeArquivo = `relatorio-securescope-${new Date().toISOString().slice(0, 10)}.pdf`;
        doc.save(nomeArquivo);

        mostrarToast('✅ Relatório PDF gerado com sucesso!', '#28a745');

    } catch (error) {
        mostrarToast('❌ Erro ao gerar relatório PDF.', '#dc3545');
    }
}

// ─────────────────────────────────────────────
// ANÁLISE DE RISCO IA (correlação + priorização + guia de remediação)
// ─────────────────────────────────────────────

async function abrirAnaliseIA(id) {

    try {
        const res = await fetch(`${API_URL}/vulnerabilidades/${id}/analise`);

        if (!res.ok) {
            mostrarToast('❌ Não foi possível carregar a análise.', '#dc3545');
            return;
        }

        const analise = await res.json();

        document.getElementById('analise-titulo').innerText =
            `Análise de Risco — ${analise.nome}`;

        document.getElementById('analise-categoria').innerText =
            `Categoria: ${analise.categoria} | Priority Score: ${analise.prioridade}`;

        document.getElementById('analise-ativo-origem').innerText =
            `Ativo: ${analise.ativo} | Origem: ${analise.origem}`;

        const listaExplicacao = document.getElementById('analise-explicacao');
        listaExplicacao.innerHTML = '';
        analise.explicacao.forEach(linha => {
            const li = document.createElement('li');
            li.innerText = linha;
            listaExplicacao.appendChild(li);
        });

        const listaDread = document.getElementById('analise-dread');
        listaDread.innerHTML = '';
        if (analise.dread) {
            const d = analise.dread;
            const linhasDread = [
                `Damage (dano): ${d.damage}/10`,
                `Reproducibility (reprodutibilidade): ${d.reproducibility}/10`,
                `Exploitability (facilidade de exploração): ${d.exploitability}/10`,
                `Affected Users (usuários afetados): ${d.affected_users}/10`,
                `Discoverability (facilidade de descoberta): ${d.discoverability}/10`,
                `Média DREAD: ${d.dread_medio}/10 (equivalente a ${d.dread_score_100}/100)`
            ];
            linhasDread.forEach(texto => {
                const li = document.createElement('li');
                li.innerText = texto;
                listaDread.appendChild(li);
            });
        }

        const listaGuia = document.getElementById('analise-guia');
        listaGuia.innerHTML = '';
        analise.guia_remediacao.forEach(passo => {
            const li = document.createElement('li');
            li.innerText = passo;
            listaGuia.appendChild(li);
        });

        document.getElementById('modal-analise-fundo').style.display = 'flex';

    } catch (error) {
        mostrarToast('❌ Erro ao conectar com a IA de análise.', '#dc3545');
    }
}

function fecharAnaliseIA() {
    document.getElementById('modal-analise-fundo').style.display = 'none';
}

document.getElementById('btn-fechar-analise').addEventListener('click', fecharAnaliseIA);

document.getElementById('modal-analise-fundo').addEventListener('click', (e) => {
    if (e.target.id === 'modal-analise-fundo') {
        fecharAnaliseIA();
    }
});