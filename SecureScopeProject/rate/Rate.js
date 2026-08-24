const botoes = document.querySelectorAll(".botoes button");
const enviarFeedback = document.querySelector("#enviar-feedback");

localStorage.removeItem("nota");

botoes.forEach((botao) => {
  botao.addEventListener("click", () => {
    const nota = botao.textContent.trim();
    localStorage.setItem("nota", nota);

    botoes.forEach((item) => {
      const selecionado = item === botao;
      item.classList.toggle("selected", selecionado);
      item.setAttribute("aria-pressed", String(selecionado));
    });
  });
});

enviarFeedback?.addEventListener("click", (evento) => {
  if (!localStorage.getItem("nota")) {
    evento.preventDefault();
    window.alert("Selecione uma nota de 1 a 5 antes de enviar.");
  }
});
