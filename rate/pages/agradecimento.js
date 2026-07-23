function pegarNota() {
    let nota = localStorage.getItem("nota")
    let paragrafoNota = document.querySelector(".paragrafo_nota")
    if (nota) {
        paragrafoNota.innerHTML = `Você selecionou ${nota} de 5`
    } else {
        paragrafoNota.innerHTML = "Obrigado pelo seu feedback!"
    }
}

pegarNota()