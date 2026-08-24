const API_URL = window.location.origin;

function getCookie(nome) {
    const prefixo = `${encodeURIComponent(nome)}=`;
    const item = document.cookie.split('; ').find((cookie) => cookie.startsWith(prefixo));
    return item ? decodeURIComponent(item.slice(prefixo.length)) : '';
}

// O JWT fica em cookie HttpOnly. O JavaScript envia apenas o token CSRF
// separado, que nao concede acesso a conta por si so.
function getAuthHeaders(extra = {}) {
    const headers = { 'Content-Type': 'application/json', ...extra };
    const csrfToken = getCookie('csrf_access_token');
    if (csrfToken) headers['X-CSRF-TOKEN'] = csrfToken;
    return headers;
}

function usuarioEstaLogado() {
    return Boolean(localStorage.getItem('ss_nome'));
}

// M3 — Atualiza o botão da navbar com o estado de autenticação
function atualizarBotaoAuth() {
    const btn = document.getElementById('btn-auth');
    if (!btn) return;
    const nome = localStorage.getItem('ss_nome');
    if (nome) {
        btn.textContent = nome;
        btn.title = 'Clique para abrir o menu';
        btn.onclick = (e) => { e.stopPropagation(); toggleMenuAuth(); };
        btn.classList.add('is-authenticated');
    } else {
        btn.textContent = 'Entrar';
        btn.title = '';
        btn.onclick = abrirModalAuth;
        btn.classList.remove('is-authenticated');
        fecharMenuAuth();
    }
}

// M3 — Abre/fecha o menu dropdown (Configurações / Sair) do usuário logado
function toggleMenuAuth() {
    const menu = document.getElementById('menu-auth');
    if (!menu) return;
    menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
}

function fecharMenuAuth() {
    const menu = document.getElementById('menu-auth');
    if (menu) menu.style.display = 'none';
}

// Fecha o menu ao clicar fora dele
document.addEventListener('click', (e) => {
    const wrapper = document.getElementById('auth-wrapper');
    if (wrapper && !wrapper.contains(e.target)) fecharMenuAuth();
});

// Configurações — sem funcionalidade por enquanto (fora do escopo deste
// integrante do time); só fecha o menu.
function abrirConfiguracoes() {
    fecharMenuAuth();
    mostrarToast('Configurações ainda não implementadas.', 'info');
}

function abrirModalAuth() {
    // Se já está logado, o clique no botão agora abre o menu dropdown
    // (Configurações / Sair) em vez de deslogar direto.
    if (usuarioEstaLogado()) { toggleMenuAuth(); return; }
    const fundo = document.getElementById('modal-auth-fundo');
    fundo.style.display = 'flex';
    document.getElementById('auth-email').focus();
}

function fecharModalAuth() {
    document.getElementById('modal-auth-fundo').style.display = 'none';
    document.getElementById('auth-erro-login').innerText = '';
    document.getElementById('auth-erro-registro').innerText = '';
}

function mostrarAbaLogin() {
    document.getElementById('form-login').style.display = 'block';
    document.getElementById('form-registro').style.display = 'none';
    document.getElementById('aba-login').style.borderBottom = '2px solid #7b2eff';
    document.getElementById('aba-login').style.color = '#c4a1ff';
    document.getElementById('aba-registro').style.borderBottom = '2px solid transparent';
    document.getElementById('aba-registro').style.color = '#666';
}

function mostrarAbaRegistro() {
    document.getElementById('form-login').style.display = 'none';
    document.getElementById('form-registro').style.display = 'block';
    document.getElementById('aba-registro').style.borderBottom = '2px solid #7b2eff';
    document.getElementById('aba-registro').style.color = '#c4a1ff';
    document.getElementById('aba-login').style.borderBottom = '2px solid transparent';
    document.getElementById('aba-login').style.color = '#666';
}

async function fazerLogin() {
    const email = document.getElementById('auth-email').value.trim();
    const senha = document.getElementById('auth-senha').value;
    const erroEl = document.getElementById('auth-erro-login');
    erroEl.innerText = '';

    if (!email || !senha) { erroEl.innerText = 'Preencha e-mail e senha.'; return; }

    try {
        const res = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, senha })
        });
        const data = await res.json();
        if (!res.ok) { erroEl.innerText = data.erro || 'Credenciais inválidas.'; return; }

        localStorage.setItem('ss_nome', data.nome);
        localStorage.setItem('ss_email', data.email);
        fecharModalAuth();
        atualizarBotaoAuth();
        carregarDadosProtegidos(); // M3 — carrega os dados do usuário recém-logado
        mostrarToast(`Bem-vindo, ${data.nome}!`, 'sucesso');
    } catch (e) {
        erroEl.innerText = 'Erro ao conectar com o servidor.';
    }
}

async function fazerRegistro() {
    const nome  = document.getElementById('reg-nome').value.trim();
    const email = document.getElementById('reg-email').value.trim();
    const senha = document.getElementById('reg-senha').value;
    const erroEl = document.getElementById('auth-erro-registro');
    erroEl.innerText = '';

    if (!nome || !email || !senha) { erroEl.innerText = 'Preencha todos os campos.'; return; }
    if (senha.length < 12) { erroEl.innerText = 'Senha deve ter no mínimo 12 caracteres.'; return; }
    if (!/[a-z]/.test(senha) || !/[A-Z]/.test(senha) || !/\d/.test(senha)) {
        erroEl.innerText = 'Use letra maiúscula, letra minúscula e número.';
        return;
    }

    try {
        const res = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nome, email, senha })
        });
        const data = await res.json();
        if (!res.ok) { erroEl.innerText = data.erro || 'Erro ao criar conta.'; return; }

        mostrarToast('Conta criada! Faça login.', 'sucesso');
        document.getElementById('reg-nome').value = '';
        document.getElementById('reg-email').value = '';
        document.getElementById('reg-senha').value = '';
        mostrarAbaLogin();
        document.getElementById('auth-email').value = email;
    } catch (e) {
        erroEl.innerText = 'Erro ao conectar com o servidor.';
    }
}

async function fazerLogout() {
    try {
        await fetch(`${API_URL}/auth/logout`, {
            method: 'POST',
            headers: getAuthHeaders(),
            credentials: 'same-origin'
        });
    } catch (e) {
        // A limpeza local continua mesmo se a sessao ja tiver expirado.
    }
    localStorage.removeItem('ss_nome');
    localStorage.removeItem('ss_email');
    atualizarBotaoAuth();
    mostrarEstadoDeslogado(); // M3 — limpa da tela os dados do usuário anterior
    mostrarToast('Sessão encerrada.', 'info');
}

// M3 — Dispara os 4 carregamentos que dependem de login (dados são por
// usuário). Chamado no window.onload (se já houver token) e logo após um
// login bem-sucedido.
function carregarDadosProtegidos() {
    carregarVulnerabilidades();
    carregarInsightsIA();
    carregarSLAWidget();
    carregarKPIsGovernance();
}

// M3 — Estado exibido quando ninguém está logado: tabela vazia com CTA de
// login, em vez de deixar os painéis girando em "carregando" pra sempre.
function mostrarEstadoDeslogado() {
    const tbody = document.getElementById('tabelaCorpo');
    if (tbody) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="tabela-vazia">
                    Faça login para ver suas vulnerabilidades.
                </td>
            </tr>
        `;
    }
    const iaLoading = document.getElementById('ia-loading');
    if (iaLoading) iaLoading.innerText = 'Faça login para ver os insights da IA.';
    const iaStats = document.getElementById('ia-stats-content');
    if (iaStats) iaStats.style.display = 'none';
    const slaBox = document.getElementById('sla-status-box');
    if (slaBox) slaBox.style.display = 'none';
}

// Ícones SVG inline (herdam a cor via currentColor), substituem os emojis
// que estavam espalhados pelo JS.
const ICONS = {
    checkCircle: '<svg class="icon" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    xCircle: '<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    alertTriangle: '<svg class="icon" viewBox="0 0 24 24"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    zap: '<svg class="icon" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
    search: '<svg class="icon" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    target: '<svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>'
};

let endpointAtual = '/vulnerabilidades';
let debounceSugestaoTimer = null;
let sugestaoAtual = null;

// Estado do wizard interativo da IA
let categoriaWizardAtual = null;
let perguntasWizard = [];
let indiceWizard = 0;
let respostasWizard = {};

async function sincronizarSessao() {
    try {
        const response = await fetch(`${API_URL}/auth/me`, { credentials: 'same-origin' });
        if (!response.ok) throw new Error('sessao_invalida');
        const usuario = await response.json();
        localStorage.setItem('ss_nome', usuario.nome);
        localStorage.setItem('ss_email', usuario.email);
        return true;
    } catch (e) {
        localStorage.removeItem('ss_nome');
        localStorage.removeItem('ss_email');
        return false;
    }
}

window.onload = async () => {
    carregarOrigens();
    inicializarScanner(); // Scanner IA — configura abas e eventos
    const sessaoAtiva = await sincronizarSessao();
    atualizarBotaoAuth();

    // M3 — as rotas de dados (vulnerabilidades, insights, SLA, governança)
    // agora exigem login, já que os dados são por usuário. Só carrega se
    // já existir um token salvo; senão deixa o painel no estado vazio
    // (ver mensagens em atualizarBotaoAuth/fazerLogin).
    if (sessaoAtiva) {
        carregarDadosProtegidos();
    } else {
        mostrarEstadoDeslogado();
    }

    // Abre modal de auth automaticamente quando o usuário vem da Home
    // via ?auth=login ou ?auth=registro (e ainda não está logado)
    if (!sessaoAtiva) {
        const authParam = new URLSearchParams(window.location.search).get('auth');
        if (authParam === 'login' || authParam === 'registro') {
            abrirModalAuth();
            if (authParam === 'registro') mostrarAbaRegistro();
        }
    }

    // Fechar modal com tecla Escape
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') fecharModalVuln();
    });
};

// ─────────────────────────────────────────────
// MODAL — Nova Vulnerabilidade
// ─────────────────────────────────────────────

function abrirModalVuln() {
    document.getElementById('modal-vuln-fundo').classList.add('aberto');
    document.body.style.overflow = 'hidden';
    setTimeout(() => {
        const input = document.getElementById('nome');
        if (input) input.focus();
    }, 100);
}

function fecharModalVuln() {
    document.getElementById('modal-vuln-fundo').classList.remove('aberto');
    document.body.style.overflow = '';
}

function fecharModalVulnFundo(event) {
    if (event.target === document.getElementById('modal-vuln-fundo')) {
        fecharModalVuln();
    }
}

// Mapa tipo -> cor + ícone. As cores são as mesmas que já existiam
// espalhadas pelos chamadas de mostrarToast (nenhuma cor nova).
const TOAST_TIPOS = {
    sucesso: { cor: '#28a745', icone: ICONS.checkCircle },
    erro:    { cor: '#dc3545', icone: ICONS.xCircle },
    critico: { cor: '#dc3545', icone: ICONS.zap },
    alerta:  { cor: '#e0a800', icone: ICONS.alertTriangle },
    info:    { cor: '#2c3e50', icone: ICONS.alertTriangle }
};

function mostrarToast(msg, tipo = 'info') {
    const toast = document.getElementById('toast');
    const config = TOAST_TIPOS[tipo] || TOAST_TIPOS.info;

    toast.innerHTML = config.icone + '<span>' + msg + '</span>';
    toast.style.background = config.cor;
    toast.style.display = 'flex';

    setTimeout(() => {
        toast.style.display = 'none';
    }, 3000);
}

async function carregarVulnerabilidades(endpoint = '/vulnerabilidades') {

    endpointAtual = endpoint;

    const response = await fetch(`${API_URL}${endpoint}`, {
        headers: getAuthHeaders()  // M3 — rota agora exige token (isolamento por usuário)
    });

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

        let classeBadge = 'badge-moderada';
        if (prioridade >= 90) {
            classeBadge = 'badge-critica';
        } else if (prioridade >= 75) {
            classeBadge = 'badge-alta';
        }

        tr.innerHTML = `
            <td>${vuln.nome}</td>
            <td>${vuln.ativo || '—'}</td>
            <td>${vuln.impacto}</td>
            <td>${vuln.frequencia}</td>
            <td>${vuln.gravidade}</td>
            <td><strong>${score.toFixed(2)}</strong></td>
            <td>
                <span class="badge-prioridade ${classeBadge}">
                    <span class="badge-dot"></span>${prioridade.toFixed(1)}
                </span>
            </td>
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

                <button class="btn-analisar icon-inline"
                    onclick="abrirAnaliseIA(${vuln.id})">
                    ${ICONS.search}Analisar
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
        ambiente_producao: respostasWizard.ambiente_producao || false,
        // M1 — Motor tripartido CVSS + EPSS + KEV
        cvss_score: parseFloat(document.getElementById('cvss_score').value) || 0.0,
        epss_score: parseFloat(document.getElementById('epss_score').value) || 0.0,
        cve_id: document.getElementById('cve_id').value.trim() || '',
        no_kev: document.getElementById('no_kev').checked || false
    };

        const res = await fetch(`${API_URL}/vulnerabilidades`, {
            method: 'POST',
            headers: getAuthHeaders(),
        body: JSON.stringify(payload)
    });

    const data = await res.json();

    const motorUsado = (payload.no_kev || payload.cvss_score > 0) ? 'v2 (CVSS+EPSS+KEV)' : 'legado';
    const slaInfo = data.sla_prioridade ? ` | SLA: ${data.sla_prioridade} (${data.sla_prazo_dias}d)` : '';
    mostrarToast(
        `"${payload.nome}" adicionada! Risk Index™: ${data['Risk Index™']} | Prioridade: ${data.prioridade}${slaInfo}`,
        payload.no_kev ? 'critico' : 'sucesso'
    );

    document.getElementById('formVuln').reset();
    esconderSugestaoIA();
    esconderWizard();
    fecharModalVuln();

    carregarVulnerabilidades();
    carregarSLAWidget();
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
            headers: getAuthHeaders(),
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
        document.getElementById('wizard-resumo-texto').innerHTML =
            `${ICONS.checkCircle}Análise de contexto concluída — ${ativos} de ${perguntasWizard.length} riscos ativos detectados.`;
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
        method: 'PUT',
        headers: getAuthHeaders()
    });

    mostrarToast(
        `Vulnerabilidade #${id} validada!`,
        'sucesso'
    );

    carregarVulnerabilidades();
}

async function acionarCircuitBreaker(id) {

    const confirmar = confirm(
        "ALERTA CRÍTICO: deseja isolar esta ameaça?"
    );

    if (!confirmar) return;

    await fetch(`${API_URL}/circuit-breaker/${id}`, {
        method: 'POST',
        headers: getAuthHeaders()
    });

    mostrarToast(
        `Circuit Breaker acionado!`,
        'critico'
    );

    carregarVulnerabilidades();
}

async function carregarInsightsIA() {

    try {

        const res = await fetch(`${API_URL}/ia/insights`, {
            headers: getAuthHeaders()  // M3 — rota agora exige token
        });

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
                li.className = 'icon-inline';
                const icone = msg.includes('concentração de risco') ? ICONS.target : ICONS.alertTriangle;
                li.innerHTML = icone + '<span>' + msg + '</span>';
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
        mostrarToast('Gerando relatório de governança...', 'info');

        // M5 — Buscar dados de 3 endpoints em paralelo
        const [resVulns, resInsights, resSlas] = await Promise.all([
            fetch(`${API_URL}/relatorio`, { headers: getAuthHeaders() }),
            fetch(`${API_URL}/ia/insights`, { headers: getAuthHeaders() }),
            fetch(`${API_URL}/sla/status`, { headers: getAuthHeaders() })
        ]);

        const dados    = await resVulns.json();
        const insights = await resInsights.json();
        const slas     = await resSlas.json();

        if (!dados || dados.length === 0) {
            mostrarToast('Nenhuma vulnerabilidade para gerar relatório.', 'alerta');
            return;
        }

        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        const dataGeracao = new Date().toLocaleString('pt-BR');
        const dataArquivo = new Date().toISOString().slice(0, 10);
        const ROXO       = [123, 46, 255];
        const AZUL_ESCURO = [44, 62, 80];

        // ─── CAPA ────────────────────────────────────────────────────────────
        doc.setFillColor(...AZUL_ESCURO);
        doc.rect(0, 0, 210, 42, 'F');

        doc.setTextColor(255, 255, 255);
        doc.setFontSize(20);
        doc.setFont('helvetica', 'bold');
        doc.text('SecureScope ASPM', 14, 18);

        doc.setFontSize(13);
        doc.setFont('helvetica', 'normal');
        doc.text('Relatório de Governança de Risco', 14, 28);

        doc.setFontSize(9);
        doc.setTextColor(180, 190, 205);
        doc.text(`Gerado em: ${dataGeracao}`, 14, 37);

        // ─── RESUMO EXECUTIVO ─────────────────────────────────────────────────
        doc.setTextColor(...AZUL_ESCURO);
        doc.setFontSize(13);
        doc.setFont('helvetica', 'bold');
        doc.text('Resumo Executivo', 14, 54);

        doc.setDrawColor(...ROXO);
        doc.setLineWidth(0.5);
        doc.line(14, 56, 196, 56);

        const slasArr     = Array.isArray(slas) ? slas : [];
        const totalVulns  = dados.length;
        const criticas    = dados.filter(v => parseFloat(v.prioridade ?? v.score) >= 90).length;
        const emAberto    = dados.filter(v => v.status === 'Aberta').length;
        const validadas   = dados.filter(v => v.status === 'Validada').length;
        const isoladas    = dados.filter(v => v.status === 'Isolada (Circuit Breaker)').length;
        const slaViolados = slasArr.filter(s => s.status_sla === 'Violado').length;
        const slaEmRisco  = slasArr.filter(s => s.status_sla === 'Em Risco').length;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(10);
        doc.setTextColor(55, 55, 75);

        const linhasResumo = [
            [`Total de Vulnerabilidades:`,  `${totalVulns}`],
            [`Prioridade Crítica (≥ 90):`,  `${criticas}`],
            [`Em Aberto / Validadas / Isoladas:`, `${emAberto} / ${validadas} / ${isoladas}`],
            [`SLAs Violados / Em Risco:`,   `${slaViolados} / ${slaEmRisco}`],
        ];
        if (insights.status === 'sucesso') {
            linhasResumo.push([`Risco Médio Geral:`, `${insights.risco_medio_geral}`]);
            linhasResumo.push([`Pior Risco Registrado:`, `${insights.pior_risco}`]);
        }

        let yr = 64;
        linhasResumo.forEach(([label, valor]) => {
            doc.setFont('helvetica', 'bold');
            doc.text(label, 14, yr);
            doc.setFont('helvetica', 'normal');
            doc.text(valor, 95, yr);
            yr += 7;
        });

        // ─── TABELA PRINCIPAL ENRIQUECIDA ─────────────────────────────────────
        const startY1 = yr + 6;
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(12);
        doc.setTextColor(...AZUL_ESCURO);
        doc.text('Vulnerabilidades Registradas', 14, startY1 - 4);

        const linhasVulns = dados.map(v => [
            (v.nome        || '').substring(0, 28),
            (v.ativo       || '—').substring(0, 16),
            v.cvss_score > 0 ? parseFloat(v.cvss_score).toFixed(1) : '—',
            parseFloat(v.score).toFixed(1),
            parseFloat(v.prioridade ?? v.score).toFixed(1),
            v.sla_prioridade || '—',
            (v.categoria   || '—').substring(0, 15),
            (v.origem      || '—').substring(0, 12),
            v.status
        ]);

        doc.autoTable({
            startY: startY1,
            head: [['Nome', 'Ativo', 'CVSS', 'Risk Index', 'Prioridade', 'SLA', 'Categoria', 'Origem', 'Status']],
            body: linhasVulns,
            headStyles: { fillColor: AZUL_ESCURO, fontSize: 8, textColor: 255 },
            styles: { fontSize: 7.5, cellPadding: 2 },
            columnStyles: {
                0: { cellWidth: 40 },
                1: { cellWidth: 26 },
                2: { cellWidth: 13 },
                3: { cellWidth: 17 },
                4: { cellWidth: 17 },
                5: { cellWidth: 11 },
                6: { cellWidth: 23 },
                7: { cellWidth: 20 }
            },
            didParseCell: (hookData) => {
                // Destaca linhas de prioridade crítica em vermelho claro
                if (hookData.section === 'body') {
                    const prioridade = parseFloat(dados[hookData.row.index]?.prioridade ?? 0);
                    if (prioridade >= 90) {
                        hookData.cell.styles.fillColor  = [255, 235, 235];
                        hookData.cell.styles.textColor  = [140, 0, 0];
                    }
                }
            }
        });

        // ─── TABELA DE STATUS DE SLAs ─────────────────────────────────────────
        if (slasArr.length > 0) {
            const alturaRestante = doc.internal.pageSize.height - doc.lastAutoTable.finalY;
            if (alturaRestante < 70) doc.addPage();

            const slaY = doc.lastAutoTable.finalY + 12;
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(12);
            doc.setTextColor(...AZUL_ESCURO);
            doc.text('Status de SLAs de Remediação', 14, slaY - 4);

            const linhasSla = slasArr.map(s => {
                const diasInfo = s.dias_restantes < 0
                    ? `${Math.abs(s.dias_restantes)}d em atraso`
                    : `${s.dias_restantes}d restantes`;
                return [
                    (s.nome || '').substring(0, 38),
                    s.nivel       || '—',
                    `${s.prazo_dias} dias`,
                    diasInfo,
                    s.status_sla
                ];
            });

            doc.autoTable({
                startY: slaY,
                head: [['Vulnerabilidade', 'Nível', 'Prazo', 'Dias Restantes', 'Status SLA']],
                body: linhasSla,
                headStyles: { fillColor: ROXO, fontSize: 8, textColor: 255 },
                styles: { fontSize: 8, cellPadding: 2 },
                didParseCell: (hookData) => {
                    if (hookData.section === 'body' && hookData.column.index === 4) {
                        const st = hookData.cell.raw;
                        if      (st === 'Violado')  { hookData.cell.styles.textColor = [180, 0, 0];   hookData.cell.styles.fontStyle = 'bold'; }
                        else if (st === 'Em Risco') { hookData.cell.styles.textColor = [160, 100, 0]; }
                        else                        { hookData.cell.styles.textColor = [0, 120, 0];   }
                    }
                }
            });
        }

        // ─── RODAPÉ EM TODAS AS PÁGINAS ───────────────────────────────────────
        const pageCount = doc.internal.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(8);
            doc.setTextColor(160, 160, 175);
            doc.text(
                `SecureScope ASPM  |  Relatório Confidencial  |  Página ${i} de ${pageCount}`,
                105,
                doc.internal.pageSize.height - 8,
                { align: 'center' }
            );
        }

        doc.save(`relatorio-securescope-${dataArquivo}.pdf`);
        mostrarToast('Relatório de governança gerado com sucesso!', 'sucesso');

    } catch (error) {
        console.error('Erro ao gerar PDF:', error);
        mostrarToast('Erro ao gerar relatório PDF.', 'erro');
    }
}

// ─────────────────────────────────────────────
// ANÁLISE DE RISCO IA (correlação + priorização + guia de remediação)
// ─────────────────────────────────────────────

async function abrirAnaliseIA(id) {

    try {
        const res = await fetch(`${API_URL}/vulnerabilidades/${id}/analise`, {
            headers: getAuthHeaders()  // M3 — rota agora exige token
        });

        if (!res.ok) {
            mostrarToast('Não foi possível carregar a análise.', 'erro');
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
        mostrarToast('Erro ao conectar com a IA de análise.', 'erro');
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

// ─────────────────────────────────────────────
// SLA WIDGET
// ─────────────────────────────────────────────
async function carregarSLAWidget() {
    try {
        const res = await fetch(`${API_URL}/sla/status`, {
            headers: getAuthHeaders()  // M3 — rota agora exige token
        });
        if (!res.ok) return;
        const dados = await res.json();

        // O endpoint retorna um array de objetos — Bug M2 corrigido
        if (!Array.isArray(dados) || dados.length === 0) return;

        const violados = dados.filter(s => s.status_sla === 'Violado');
        const emRisco  = dados.filter(s => s.status_sla === 'Em Risco');

        // Só exibe o widget se houver algo crítico para mostrar
        if (violados.length === 0 && emRisco.length === 0) return;

        const box = document.getElementById('sla-status-box');
        if (!box) return;
        box.style.display = 'block';

        // Resumo de contagem
        const partes = [];
        if (violados.length > 0) partes.push(`${violados.length} violado(s)`);
        if (emRisco.length  > 0) partes.push(`${emRisco.length} em risco`);
        document.getElementById('sla-criticos').innerText = partes.join(' / ');

        // Lista dos mais críticos (até 3)
        const criticos = [...violados, ...emRisco].slice(0, 3);
        const lista = criticos.map(v => {
            const diasInfo = v.dias_restantes < 0
                ? `${Math.abs(v.dias_restantes)}d em atraso`
                : `${v.dias_restantes}d restantes`;
            return `${v.nome.substring(0, 25)} (${v.nivel} – ${diasInfo})`;
        }).join(' | ');

        document.getElementById('sla-lista').innerText = lista;

    } catch (error) {
        console.error('Erro ao carregar SLAs', error);
    }
}

// ─────────────────────────────────────────────
// GOVERNANCE KPIs (M4 / M6)
// ─────────────────────────────────────────────
async function carregarKPIsGovernance() {
    try {
        const [resMat, resKpi] = await Promise.all([
            fetch(`${API_URL}/governance/maturity`, { headers: getAuthHeaders() }),
            fetch(`${API_URL}/governance/kpis`, { headers: getAuthHeaders() })
        ]);
        
        if (!resMat.ok || !resKpi.ok) return;

        const mat = await resMat.json();
        const kpis = await resKpi.json();

        document.getElementById('governance-kpis-box').style.display = 'block';

        // SAMM Maturity
        document.getElementById('kpi-samm-nivel').innerText = (mat.nivel_samm != null) ? mat.nivel_samm : 'N/A';
        document.getElementById('kpi-samm-desc').innerText = mat.descricao || '';
        
        // SLA Breach Rate
        const slaBreach = (kpis.sla_breach_rate_percent != null) ? kpis.sla_breach_rate_percent : 0;
        document.getElementById('kpi-sla-breach').innerText = `${slaBreach}%`;
        if (slaBreach > 15) {
            document.getElementById('kpi-sla-breach').style.color = '#ff4444';
        } else if (slaBreach > 5) {
            document.getElementById('kpi-sla-breach').style.color = '#ffbb33';
        } else {
            document.getElementById('kpi-sla-breach').style.color = '#00C851';
        }

        // Scan Coverage
        const scanCoverage = (kpis.scan_coverage_rate_percent != null) ? kpis.scan_coverage_rate_percent : 0;
        document.getElementById('kpi-scan-coverage').innerText = `${scanCoverage}%`;
        if (scanCoverage < 80) {
            document.getElementById('kpi-scan-coverage').style.color = '#ffbb33';
        } else {
            document.getElementById('kpi-scan-coverage').style.color = '#00C851';
        }

    } catch (error) {
        console.error('Erro ao carregar KPIs de Governança', error);
    }
}

// ═════════════════════════════════════════════════════
// SCANNER COM IA — SCA / SAST / DAST
// ═════════════════════════════════════════════════════

// Estado interno do scanner
const _scanner = {
    abaAtiva: 'sca',
    arquivoSCA: null,
    arquivoSAST: null,
    rodando: false
};

/**
 * inicializarScanner — configura listeners de teclado para DAST
 * e garante que os painéis comecem no estado correto.
 */
function inicializarScanner() {
    // DAST: habilita/desabilita botão conforme URL digitada
    const inputUrl = document.getElementById('dast-url');
    if (inputUrl) {
        inputUrl.addEventListener('input', onUrlChanged);
        inputUrl.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') iniciarScan('dast');
        });
    }
}

/**
 * mudarAbaScan — alterna entre as abas SCA / SAST / DAST.
 * @param {string} aba — 'sca' | 'sast' | 'dast'
 */
function mudarAbaScan(aba) {
    _scanner.abaAtiva = aba;

    // Atualiza classes das abas
    ['sca', 'sast', 'dast'].forEach(t => {
        const tab = document.getElementById(`tab-${t}`);
        const panel = document.getElementById(`panel-${t}`);
        if (tab) tab.classList.toggle('active', t === aba);
        if (tab) tab.setAttribute('aria-selected', t === aba);
        if (panel) panel.style.display = t === aba ? 'block' : 'none';
    });

    // Fecha resultado anterior ao trocar de aba
    fecharResultadoScan();
}

// ─── DRAG & DROP ──────────────────────────────────────────────────────

function handleDragOver(event, tipo) {
    event.preventDefault();
    document.getElementById(`upload-zone-${tipo}`)?.classList.add('dragover');
}

function handleDragLeave(event, tipo) {
    document.getElementById(`upload-zone-${tipo}`)?.classList.remove('dragover');
}

function handleDrop(event, tipo) {
    event.preventDefault();
    const zone = document.getElementById(`upload-zone-${tipo}`);
    zone?.classList.remove('dragover');
    const file = event.dataTransfer?.files?.[0];
    if (file) definirArquivo(tipo, file);
}

/**
 * onFileSelected — callback do <input type="file">
 */
function onFileSelected(tipo, input) {
    const file = input?.files?.[0];
    if (file) definirArquivo(tipo, file);
}

/**
 * definirArquivo — valida extensão e armazena o arquivo no estado.
 */
function definirArquivo(tipo, file) {
    const extensoesValidas = {
        sca:  ['.txt'],
        sast: ['.py', '.zip']
    };
    const nomeMin = file.name.toLowerCase();
    const validos = extensoesValidas[tipo] || [];
    const ok = validos.some(ext => nomeMin.endsWith(ext));

    if (!ok) {
        mostrarToast(`Tipo de arquivo inválido. Use: ${validos.join(' ou ')}`, 'erro');
        return;
    }

    if (tipo === 'sca')  _scanner.arquivoSCA  = file;
    if (tipo === 'sast') _scanner.arquivoSAST = file;

    // Atualiza visual da upload zone
    const zone = document.getElementById(`upload-zone-${tipo}`);
    const info = document.getElementById(`file-info-${tipo}`);
    if (zone) zone.classList.add('has-file');
    if (info) {
        info.innerHTML = `
            <svg class="icon" viewBox="0 0 24 24" style="color:#00C851;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            ${file.name} (${(file.size / 1024).toFixed(1)} KB)
        `;
    }

    const btn = document.getElementById(`btn-scan-${tipo}`);
    if (btn) btn.disabled = false;
}

/**
 * onUrlChanged — habilita botão DAST quando a URL parece válida.
 */
function onUrlChanged() {
    const url = document.getElementById('dast-url')?.value?.trim() || '';
    const btn = document.getElementById('btn-scan-dast');
    if (btn) btn.disabled = !url.startsWith('http');
}

// ─── SCAN DISPATCHER ──────────────────────────────────────────────────

/**
 * iniciarScan — ponto central de entrada; despacha para SCA/SAST/DAST.
 * @param {string} tipo — 'sca' | 'sast' | 'dast'
 */
async function iniciarScan(tipo) {
    if (_scanner.rodando) return;

    if (!usuarioEstaLogado()) {
        mostrarToast('Faça login antes de executar um scan.', 'alerta');
        abrirModalAuth();
        return;
    }

    _scanner.rodando = true;
    fecharResultadoScan();
    mostrarLoadingScan(`Executando scan ${tipo.toUpperCase()} com IA...`);

    try {
        let dados;
        if (tipo === 'sca')  dados = await executarScannerSCA(_scanner.arquivoSCA);
        if (tipo === 'sast') dados = await executarScannerSAST(_scanner.arquivoSAST);
        if (tipo === 'dast') dados = await executarScannerDAST(
            document.getElementById('dast-url')?.value?.trim()
        );

        if (dados) {
            renderizarResultadoScanner(dados, tipo);
            // Recarrega tabela para refletir novos achados importados
            if (usuarioEstaLogado()) {
                carregarVulnerabilidades();
                carregarSLAWidget();
                carregarInsightsIA();
                carregarKPIsGovernance();
            }
        }
    } catch (err) {
        ocultarLoadingScan();
        console.error('[Scanner]', err);
        mostrarToast('Erro inesperado no scanner. Veja o console.', 'erro');
    } finally {
        _scanner.rodando = false;
    }
}

// ─── API CALLS ────────────────────────────────────────────────────────

/**
 * executarScannerSCA — POST /scanner/analisar (form-data, campo "arquivo").
 */
async function executarScannerSCA(arquivo) {
    if (!arquivo) {
        mostrarToast('Selecione o requirements.txt primeiro.', 'alerta');
        ocultarLoadingScan();
        return null;
    }
    const form = new FormData();
    form.append('arquivo', arquivo);

    const res = await fetch(`${API_URL}/scanner/analisar`, {
        method: 'POST',
        headers: { 'X-CSRF-TOKEN': getCookie('csrf_access_token') },
        credentials: 'same-origin',
        body: form
    });
    return tratarRespostaScan(res, 'SCA');
}

/**
 * executarScannerSAST — POST /scanner/analisar-codigo (form-data, campo "arquivo").
 */
async function executarScannerSAST(arquivo) {
    if (!arquivo) {
        mostrarToast('Selecione um arquivo .py ou .zip primeiro.', 'alerta');
        ocultarLoadingScan();
        return null;
    }
    const form = new FormData();
    form.append('arquivo', arquivo);

    const res = await fetch(`${API_URL}/scanner/analisar-codigo`, {
        method: 'POST',
        headers: { 'X-CSRF-TOKEN': getCookie('csrf_access_token') },
        credentials: 'same-origin',
        body: form
    });
    return tratarRespostaScan(res, 'SAST');
}

/**
 * executarScannerDAST — POST /scanner/analisar-url (JSON body).
 */
async function executarScannerDAST(url) {
    if (!url) {
        mostrarToast('Informe uma URL válida antes de iniciar.', 'alerta');
        ocultarLoadingScan();
        return null;
    }
    const res = await fetch(`${API_URL}/scanner/analisar-url`, {
        method: 'POST',
        headers: getAuthHeaders(),
        credentials: 'same-origin',
        body: JSON.stringify({ url })
    });
    return tratarRespostaScan(res, 'DAST');
}

/**
 * tratarRespostaScan — trata códigos de erro HTTP e devolve JSON.
 */
async function tratarRespostaScan(res, nomeTipo) {
    ocultarLoadingScan();

    if (res.status === 401) {
        mostrarToast('Sessão expirada. Faça login novamente.', 'erro');
        fazerLogout();
        return null;
    }

    let json;
    try { json = await res.json(); } catch { json = {}; }

    if (res.status === 400) {
        // Erros de validação / SSRF bloqueado
        const msg = json.erro || json.message || `Erro 400 no scan ${nomeTipo}.`;
        mostrarToast(msg, 'erro');
        return null;
    }

    if (res.status === 502 || res.status === 503) {
        // ZAP ou serviço externo indisponível
        const msg = json.erro || `Serviço ${nomeTipo} indisponível. Tente novamente mais tarde.`;
        mostrarToast(msg, 'alerta');
        return null;
    }

    if (!res.ok) {
        const msg = json.erro || `Erro ${res.status} ao executar scan ${nomeTipo}.`;
        mostrarToast(msg, 'erro');
        return null;
    }

    return json;
}

// ─── UI HELPERS ───────────────────────────────────────────────────────

function mostrarLoadingScan(texto = 'Executando análise com IA...') {
    const el = document.getElementById('scanner-loading');
    const txt = document.getElementById('scanner-loading-text');
    if (txt) txt.textContent = texto;
    if (el)  el.style.display = 'flex';
    // Desabilita botões durante o scan
    ['btn-scan-sca', 'btn-scan-sast', 'btn-scan-dast'].forEach(id => {
        const b = document.getElementById(id);
        if (b) b.disabled = true;
    });
}

function ocultarLoadingScan() {
    const el = document.getElementById('scanner-loading');
    if (el) el.style.display = 'none';
    // Re-habilita apenas o botão da aba com arquivo selecionado
    const tipo = _scanner.abaAtiva;
    if (tipo === 'sca'  && _scanner.arquivoSCA)  document.getElementById('btn-scan-sca').disabled  = false;
    if (tipo === 'sast' && _scanner.arquivoSAST) document.getElementById('btn-scan-sast').disabled = false;
    if (tipo === 'dast') {
        const url = document.getElementById('dast-url')?.value?.trim();
        const btn = document.getElementById('btn-scan-dast');
        if (btn) btn.disabled = !url?.startsWith('http');
    }
}

function fecharResultadoScan() {
    const el = document.getElementById('scanner-resultado');
    if (el) el.style.display = 'none';
}

/**
 * renderizarResultadoScanner — exibe os dados do scan de forma visual.
 * @param {object} dados — JSON retornado pela API
 * @param {string} tipo  — 'sca' | 'sast' | 'dast'
 */
function renderizarResultadoScanner(dados, tipo) {
    const tipoLabels = { sca: 'SCA — Dependências', sast: 'SAST — Código', dast: 'DAST — URL' };
    const total  = dados.total_vulnerabilidades_encontradas ?? dados.vulnerabilidades?.length ?? 0;
    const descartados = dados.achados_descartados ?? 0;
    const triagem = dados.triagem_aplicada ?? false;
    const mockZAP = dados.zap_mock_usado ?? false;
    const vulns = dados.vulnerabilidades ?? [];

    // ─ Header
    const tituloEl = document.getElementById('resultado-titulo-texto');
    if (tituloEl) {
        const iconeOk = `<svg class="icon" viewBox="0 0 24 24" style="color:#00C851;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
        const iconeWarn = `<svg class="icon" viewBox="0 0 24 24" style="color:#ffc107;"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
        tituloEl.innerHTML = `${total > 0 ? iconeWarn : iconeOk} Scan ${tipoLabels[tipo]} concluído — Scan ID #${dados.scan_id ?? '—'}`;
    }

    // ─ Stats cards
    const statsEl = document.getElementById('resultado-stats');
    if (statsEl) {
        const totalCor  = total  > 0 ? 'danger' : 'success';
        const descCor   = descartados > 0 ? 'success' : 'info';
        const triagCor  = triagem ? 'success' : 'warning';

        statsEl.innerHTML = `
            <div class="resultado-stat-card">
                <div class="resultado-stat-label">Vulnerabilidades</div>
                <div class="resultado-stat-value ${totalCor}">${total}</div>
            </div>
            <div class="resultado-stat-card">
                <div class="resultado-stat-label">Descartadas pela IA</div>
                <div class="resultado-stat-value ${descCor}">${descartados}</div>
            </div>
            <div class="resultado-stat-card">
                <div class="resultado-stat-label">Triagem IA</div>
                <div class="resultado-stat-value ${triagCor}">${triagem ? 'Ativa' : 'Off'}</div>
            </div>
            ${ mockZAP ? `
            <div class="resultado-stat-card">
                <div class="resultado-stat-label">Modo ZAP</div>
                <div class="resultado-stat-value warning">Mock</div>
            </div>` : ''}
        `;
    }

    // ─ Lista de achados
    const listaEl = document.getElementById('resultado-lista');
    if (listaEl) {
        if (vulns.length === 0) {
            listaEl.innerHTML = `
                <div class="resultado-vazio">
                    <svg class="icon" viewBox="0 0 24 24" style="width:20px;height:20px;color:#00C851;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    Nenhuma vulnerabilidade crítica encontrada!
                </div>
            `;
        } else {
            listaEl.innerHTML = vulns.map((v, idx) => {
                const grav = (v.gravidade || '').toLowerCase();
                const gravClasse = grav.includes('crít') ? 'critica'
                    : grav.includes('alt') ? 'alta'
                    : grav.includes('méd') || grav.includes('med') ? 'media'
                    : 'baixa';

                const cvss   = v.cvss_score != null ? `CVSS: ${parseFloat(v.cvss_score).toFixed(1)}` : '';
                const sla    = v.sla_prioridade ? `SLA: ${v.sla_prioridade}` : '';
                const vulnId = v.vuln_id ? `#${v.vuln_id}` : '';
                const origem = v.origem || tipo.toUpperCase();

                const metas = [cvss, sla, vulnId ? `ID: ${vulnId}` : '', `Origem: ${origem}`]
                    .filter(Boolean)
                    .map(m => `<span>${m}</span>`).join('');

                const delay = idx * 60;

                return `
                    <div class="resultado-vuln-item" style="animation-delay:${delay}ms;">
                        <div class="resultado-vuln-gravidade ${gravClasse}"></div>
                        <div class="resultado-vuln-info">
                            <div class="resultado-vuln-nome">${v.nome || v.cve_id || '—'}</div>
                            <div class="resultado-vuln-meta">${metas}</div>
                        </div>
                        <span class="badge-prioridade ${gravClasse === 'critica' ? 'badge-critica' : gravClasse === 'alta' ? 'badge-alta' : 'badge-moderada'}">
                            <span class="badge-dot"></span>${v.gravidade || '—'}
                        </span>
                    </div>
                `;
            }).join('');

            if (triagem && descartados > 0) {
                listaEl.innerHTML += `
                    <div style="padding: 6px 0;">
                        <span class="resultado-triagem-badge">
                            <svg class="icon" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>
                            Triagem IA: ${descartados} achado(s) descartado(s) automaticamente
                        </span>
                    </div>
                `;
            }
        }
    }

    // Exibe o bloco de resultado
    const resultadoEl = document.getElementById('scanner-resultado');
    if (resultadoEl) resultadoEl.style.display = 'block';

    // Scroll suave até o resultado
    resultadoEl?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    const tipoLabel = tipoLabels[tipo] || tipo.toUpperCase();
    mostrarToast(
        total > 0
            ? `Scan ${tipoLabel}: ${total} vuln(s) encontrada(s).`
            : `Scan ${tipoLabel} concluído — nenhuma vulnerabilidade!`,
        total > 0 ? 'alerta' : 'sucesso'
    );
}
