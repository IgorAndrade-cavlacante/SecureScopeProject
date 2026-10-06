/* Gestão de achados e scans. Dados remotos sempre escapados antes de renderizar. */
const gestaoEstado = { equipes: [], pagina: 1, timer: null, epoch: 0, detalhe: null, historico: '', request: 0, busy: false };
const elG = (id) => document.getElementById(id);
const escG = (value) => escaparHtml(value ?? '');

async function apiG(path, options = {}) {
    const generation = gestaoEstado.epoch;
    const response = await fetch(path, { credentials: 'same-origin', headers: getAuthHeaders(), ...options });
    const data = await response.json().catch(() => ({}));
    if (generation !== gestaoEstado.epoch) throw new Error('Sessão alterada.');
    if (!response.ok) {
        if (response.status === 401) {
            localStorage.removeItem('ss_nome'); localStorage.removeItem('ss_email');
            atualizarBotaoAuth(); mostrarEstadoDeslogado(); abrirModalAuth();
        }
        throw new Error(data.erro || 'Não foi possível concluir a operação.');
    }
    return data;
}

async function tentarG(action) {
    try { await action(); } catch (error) { mostrarToast(error.message, 'erro'); }
}

function filtrosG() {
    return new URLSearchParams([...new FormData(elG('filtros-gestao'))].filter(([, value]) => value));
}

function limparFiltrosG() {
    elG('filtros-gestao').reset();
    carregarVulnerabilidades();
}

async function exportarG(formato) {
    await tentarG(async () => {
        const generation = gestaoEstado.epoch;
        const response = await fetch(`/gestao/exportar/${formato}?${filtrosG()}`, { headers: getAuthHeaders() });
        if (!response.ok) throw new Error((await response.json()).erro || 'Falha ao exportar.');
        const blob = await response.blob();
        if (generation !== gestaoEstado.epoch) return;
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = `securescope.${formato}`;
        document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
}

function opcoesEquipesG(selected = '', base = 'Meus achados') {
    return `<option value="">${escG(base)}</option>` + gestaoEstado.equipes.map(e =>
        `<option value="${Number(e.id)}" ${String(e.id) === String(selected) ? 'selected' : ''}>${escG(e.nome)} (${escG(e.papel)})</option>`).join('');
}

async function atualizarEquipesG() {
    gestaoEstado.equipes = await apiG('/equipes');
    const selected = elG('filtro-equipe').value;
    elG('filtro-equipe').innerHTML = opcoesEquipesG(selected);
    const manage = elG('equipe-gerenciar').value;
    elG('equipe-gerenciar').innerHTML = opcoesEquipesG(manage, 'Selecione uma equipe');
}

async function gestaoAtualizar() {
    if (!usuarioEstaLogado()) return;
    elG('recursos-gestao').hidden = false;
    await tentarG(async () => {
        await atualizarEquipesG();
        const prefs = await apiG('/preferencias/alertas'); elG('alerta-dias').value = prefs.dias;
        await Promise.all([carregarScansG(), carregarAlertasG()]);
    });
    agendarGestaoG();
}

function agendarGestaoG() {
    clearTimeout(gestaoEstado.timer);
    if (!usuarioEstaLogado()) return;
    const generation = gestaoEstado.epoch;
    gestaoEstado.timer = setTimeout(async () => {
        if (!usuarioEstaLogado() || generation !== gestaoEstado.epoch) return;
        try { await Promise.all([carregarScansG(), carregarAlertasG()]); } catch (error) {
            elG('scans-lista').textContent = error.message;
        }
        if (generation === gestaoEstado.epoch) agendarGestaoG();
    }, gestaoEstado.busy ? 4000 : 15000);
}

function gestaoResetar() {
    gestaoEstado.epoch++; gestaoEstado.request++; clearTimeout(gestaoEstado.timer);
    gestaoEstado.equipes = []; gestaoEstado.detalhe = null; gestaoEstado.historico = ''; gestaoEstado.pagina = 1;
    elG('recursos-gestao').hidden = true;
    ['scans-lista', 'alertas-lista', 'membros-lista', 'comparacao-lista', 'gestao-detalhe-conteudo'].forEach(id => elG(id).replaceChildren());
    elG('gestao-detalhe').close(); elG('filtros-gestao').reset();
    elG('filtro-equipe').innerHTML = '<option value="">Meus achados</option>';
    elG('filtro-origem').innerHTML = '<option value="">Todas</option>';
    elG('gestao-contagem').textContent = 'Entre para consultar os achados.';
}

async function carregarScansG() {
    const data = await apiG(`/scans?pagina=${gestaoEstado.pagina}`);
    const previous = gestaoEstado.historico;
    const signature = data.scans.map(s => `${s.id}:${s.status}`).join('|');
    gestaoEstado.historico = signature;
    gestaoEstado.busy = data.scans.some(s => ['na_fila', 'em_progresso'].includes(s.status));
    elG('scans-pagina').textContent = `Página ${data.pagina} · ${data.total} execução(ões)`;
    elG('scans-anterior').disabled = data.pagina <= 1;
    elG('scans-proxima').disabled = data.pagina * data.por_pagina >= data.total;
    elG('scans-lista').innerHTML = data.scans.map(s => `<article class="gestao-item">
        <strong>#${Number(s.id)} · ${escG(s.tipo?.toUpperCase() || 'Legado')} · ${escG(s.alvo || s.nome_arquivo)}</strong>
        <p>${escG(s.status)} · ${escG(s.etapa)} · ${Number(s.total_achados)} achado(s)</p>
        <small>Enviado: ${escG(s.data_inicio)}${s.data_fim ? ` · Finalizado: ${escG(s.data_fim)}` : ''}</small>
        ${s.status === 'na_fila' ? '<p>Aguardando o processador de scans.</p>' : ''}
        ${s.erro ? `<p class="gestao-erro">${escG(s.erro)}</p>` : ''}
        <div class="gestao-acoes"><button data-g="scan" data-id="${Number(s.id)}">Ver resultado</button>
        ${s.status === 'concluido' && s.tipo ? `<button data-g="antes" data-id="${Number(s.id)}">Usar como anterior</button><button data-g="depois" data-id="${Number(s.id)}">Usar como posterior</button>` : ''}</div>
        </article>`).join('') || '<p>Nenhuma execução registrada.</p>';
    if (previous && previous !== signature) {
        carregarVulnerabilidades(); carregarSLAWidget(); carregarKPIsGovernance();
    }
}

function paginaScansG(delta) { gestaoEstado.pagina += delta; tentarG(carregarScansG); }

async function mostrarScanG(id) {
    const s = await apiG(`/scans/${id}`);
    if (!s.resultado || s.status !== 'concluido') {
        mostrarToast(s.erro || s.etapa || 'Execução antiga sem snapshot de resultado.', 'info'); return;
    }
    renderizarResultadoScanner(s.resultado, s.tipo);
    mostrarToast(`${s.resultado.novos_achados ?? 0} novos; ${s.resultado.achados_repetidos ?? 0} já registrados.`, 'info');
    elG('scanner-resultado').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function compararScansG(event) {
    event.preventDefault();
    await tentarG(async () => {
        const data = await apiG(`/scans/comparar?antes=${encodeURIComponent(elG('scan-antes').value)}&depois=${encodeURIComponent(elG('scan-depois').value)}`);
        elG('comparacao-lista').innerHTML = [['Novos', data.novos], ['Persistentes', data.persistentes], ['Não detectados novamente', data.nao_detectados]].map(([label, rows]) =>
            `<article class="gestao-item"><h3>${label} (${rows.length})</h3>${rows.map(v => `<p>${escG(v.nome)} · ${escG(v.arquivo || v.pacote || v.url)}</p>`).join('') || '<p>Nenhum.</p>'}</article>`).join('') + `<p>${escG(data.aviso)}</p>`;
    });
}

async function carregarAlertasG() {
    const data = await apiG('/alertas');
    const unread = data.filter(a => !a.lido);
    elG('alertas-contagem').textContent = `${unread.length} alerta(s) não lido(s)`;
    elG('alertas-lista').innerHTML = unread.map(a => `<article class="gestao-item gestao-alerta">
        <strong>${escG(a.nivel)} · ${escG(a.nome)}</strong><p>Prazo: ${escG(a.prazo.replace('T', ' '))}</p>
        <div class="gestao-acoes"><button data-g="detalhe" data-id="${Number(a.id)}">Gerenciar</button><button data-g="ler" data-id="${Number(a.id)}">Marcar como lido</button></div></article>`).join('') || '<p>Nenhum alerta não lido no período configurado.</p>';
}

async function salvarAlertaG(event) {
    event.preventDefault();
    await tentarG(async () => {
        await apiG('/preferencias/alertas', { method: 'PUT', body: JSON.stringify({ dias: Number(elG('alerta-dias').value) }) });
        await carregarAlertasG(); mostrarToast('Antecedência salva.', 'sucesso');
    });
}

async function criarEquipeG(event) {
    event.preventDefault();
    await tentarG(async () => {
        const data = await apiG('/equipes', { method: 'POST', body: JSON.stringify({ nome: elG('equipe-nome').value }) });
        elG('equipe-nome').value = ''; await atualizarEquipesG(); elG('equipe-gerenciar').value = data.id;
        await membrosG(); mostrarToast('Equipe criada.', 'sucesso');
    });
}

async function membrosG() {
    const id = Number(elG('equipe-gerenciar').value);
    elG('membros-lista').replaceChildren(); elG('membro-form').hidden = true;
    if (!id) return;
    const rows = await apiG(`/equipes/${id}/membros`);
    // Ignora respostas atrasadas de outra equipe.
    if (Number(elG('equipe-gerenciar').value) !== id) return;
    const manager = gestaoEstado.equipes.find(e => e.id === id)?.papel === 'gestor';
    elG('membro-form').hidden = !manager;
    elG('membros-lista').innerHTML = rows.map(m => `<article class="gestao-item">
        <strong>${escG(m.nome)}</strong><p>${escG(m.email)} · ${escG(m.papel)}</p>
        ${manager && m.papel !== 'gestor' ? `<button data-g="remover-membro" data-equipe="${id}" data-id="${Number(m.id)}">Remover acesso</button>` : ''}</article>`).join('');
}

async function salvarMembroG(event) {
    event.preventDefault();
    await tentarG(async () => {
        await apiG(`/equipes/${Number(elG('equipe-gerenciar').value)}/membros`, {
            method: 'POST', body: JSON.stringify({ email: elG('membro-email').value, papel: elG('membro-papel').value }) });
        elG('membro-email').value = ''; await membrosG(); mostrarToast('Acesso atualizado.', 'sucesso');
    });
}

async function abrirGestao(id) { await tentarG(() => detalheG(id)); }

async function detalheG(id) {
    const data = await apiG(`/gestao/vulnerabilidades/${id}`);
    gestaoEstado.detalhe = data;
    const v = data.vulnerabilidade;
    const edit = data.papel !== 'leitor';
    const owner = data.papel === 'dono';
    const teamOptions = gestaoEstado.equipes.filter(e => e.papel !== 'leitor').map(e =>
        `<option value="${Number(e.id)}" ${e.id === v.equipe_id ? 'selected' : ''}>${escG(e.nome)}</option>`).join('');
    const members = v.equipe_id ? data.membros.filter(m => m.papel !== 'leitor') : [{ id: v.usuario_id, nome: 'Eu' }];
    elG('gestao-detalhe-conteudo').innerHTML = `<h2 id="gestao-detalhe-titulo">${escG(v.nome)}</h2>
        <p>Status: ${escG(v.status)} · Ativo: ${escG(v.ativo || 'Não informado')}</p>
        ${v.corrigida_em ? `<p>Corrigida em: ${escG(v.corrigida_em)}</p>` : ''}
        ${edit ? `<fieldset><legend>Tratamento</legend><form id="status-form" class="gestao-form">
        <label>Status<select id="novo-status"><option value="Corrigida">Corrigida</option><option value="Aberta">Reabrir</option><option value="Validada">Validada</option><option value="Isolada (Circuit Breaker)">Isolada (Circuit Breaker)</option></select></label>
        <label>Justificativa<textarea id="status-justificativa" required maxlength="1000"></textarea></label><button>Salvar status</button></form>
        <p>Reabrir conserva o prazo original de SLA. Isolamento registra uma decisão; não bloqueia a rede.</p></fieldset>` : '<p>Acesso de leitura: alterações estão restritas aos analistas e ao gestor.</p>'}
        ${owner ? `<fieldset><legend>Compartilhar com uma equipe</legend><p>Os membros poderão consultar este achado, suas evidências, comentários e histórico. Analistas e gestor poderão tratá-lo.</p>
        <form id="compartilhar-form" class="gestao-form"><label>Equipe<select id="compartilhar-equipe"><option value="">Privado</option>${teamOptions}</select></label><button>Salvar compartilhamento</button></form></fieldset>` : ''}
        ${edit ? `<form id="responsavel-form" class="gestao-form"><label>Responsável<select id="responsavel-id"><option value="">Não atribuído</option>${members.map(m => `<option value="${Number(m.id)}" ${v.responsavel_id === m.id ? 'selected' : ''}>${escG(m.nome)}</option>`).join('')}</select></label><button>Atribuir</button></form>` : ''}
        <h3>Comentários</h3>${data.comentarios.map(c => `<article class="gestao-item"><strong>${escG(c.autor)}</strong><small> · ${escG(c.criado_em)}</small><p>${escG(c.texto)}</p></article>`).join('') || '<p>Nenhum comentário.</p>'}
        ${edit ? '<form id="comentario-form" class="gestao-form"><label>Comentário<textarea id="comentario-texto" required maxlength="2000"></textarea></label><button>Adicionar comentário</button></form>' : ''}
        <details><summary>Histórico de alterações (${data.historico.length})</summary>${data.historico.map(h => `<article class="gestao-item"><small>${escG(h.data)} · ${escG(h.autor || h.responsavel)}</small><p>${escG(h.acao)}</p></article>`).join('') || '<p>Nenhuma alteração.</p>'}</details>`;
    const modal = elG('gestao-detalhe'); if (!modal.open) modal.showModal();
    const bind = (form, path, payload) => elG(form)?.addEventListener('submit', event => {
        event.preventDefault();
        tentarG(async () => {
            const button = event.submitter; if (button) button.disabled = true;
            try {
                await apiG(`/gestao/vulnerabilidades/${id}/${path}`, { method: path === 'comentarios' ? 'POST' : 'PUT', body: JSON.stringify(payload()) });
                await detalheG(id); carregarVulnerabilidades(); carregarSLAWidget(); carregarKPIsGovernance(); await carregarAlertasG();
            } finally { if (button?.isConnected) button.disabled = false; }
        });
    });
    bind('status-form', 'status', () => ({ status: elG('novo-status').value, justificativa: elG('status-justificativa').value }));
    bind('compartilhar-form', 'colaboracao', () => ({ equipe_id: Number(elG('compartilhar-equipe').value) || null }));
    bind('responsavel-form', 'colaboracao', () => ({ responsavel_id: Number(elG('responsavel-id').value) || null }));
    bind('comentario-form', 'comentarios', () => ({ texto: elG('comentario-texto').value }));
}

document.addEventListener('click', event => {
    const button = event.target.closest('button[data-g]');
    if (!button) return;
    const id = Number(button.dataset.id);
    tentarG(async () => {
        switch (button.dataset.g) {
            case 'scan': await mostrarScanG(id); break;
            case 'antes': elG('scan-antes').value = id; break;
            case 'depois': elG('scan-depois').value = id; break;
            case 'detalhe': await detalheG(id); break;
            case 'ler': await apiG(`/alertas/${id}/ler`, { method: 'POST', body: '{}' }); await carregarAlertasG(); break;
            case 'remover-membro':
                if (!confirm('Remover o acesso desse membro à equipe?')) return;
                await apiG(`/equipes/${Number(button.dataset.equipe)}/membros/${id}`, { method: 'DELETE' }); await membrosG(); break;
        }
    });
});
