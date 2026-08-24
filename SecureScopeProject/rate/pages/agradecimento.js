function pegarNota() {
  const nota = localStorage.getItem("nota");
  const paragrafoNota = document.querySelector(".paragrafo_nota");

  if (!paragrafoNota) {
    return;
  }

  paragrafoNota.textContent = nota
    ? "Você selecionou " + nota + " de 5"
    : "Obrigado pelo seu feedback!";

  if (nota) {
    localStorage.removeItem("nota");
  }
}

pegarNota();
