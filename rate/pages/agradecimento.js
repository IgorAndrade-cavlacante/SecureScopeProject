function pegarNota() {
    let nota = localStorage.getItem("nota");
    console.log(nota); // Veja o valor no console

    let paragrafoNota = document.querySelector("./paragrafo_nota");
    paragrafo_nota.innerHTML = `Você selecionou ${nota} de 5`;
}

pegarNota();