const API_URL = 'http://127.0.0.1:5000';

let endpointAtual = '/vulnerabilidades';

window.onload = () => {
    carregarVulnerabilidades();
    carregarInsightsIA();
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
                <td colspan="7" class="tabela-vazia">
                    Nenhuma vulnerabilidade registrada ainda.
                </td>
            </tr>
        `;

        return;
    }

    dados.forEach(vuln => {

        const tr = document.createElement('tr');

        const score = parseFloat(vuln.score);

        if (score > 80) {
            tr.classList.add('risco-critico');
        }

        tr.innerHTML = `
            <td>${vuln.nome}</td>
            <td>${vuln.impacto}</td>
            <td>${vuln.frequencia}</td>
            <td>${vuln.gravidade}</td>
            <td><strong>${score.toFixed(2)}</strong></td>
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
        gravidade: parseFloat(document.getElementById('gravidade').value)
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
        `✅ "${payload.nome}" adicionada! Risk Index™: ${data['Risk Index™']}`,
        '#28a745'
    );

    document.getElementById('formVuln').reset();

    carregarVulnerabilidades();
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
        }

    } catch (error) {

        document.getElementById('ia-loading').innerText =
            'Erro ao conectar com IA.';
    }
}

function voltarPadrao() {
    carregarVulnerabilidades('/vulnerabilidades');
}