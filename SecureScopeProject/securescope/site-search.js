(() => {
  const style = document.createElement("style");
  style.textContent = ".site-search-highlight { outline: 3px solid #ffd60a; outline-offset: 4px; border-radius: 4px; }";
  document.head.appendChild(style);

  document.querySelectorAll(".search").forEach((container) => {
    const input = container.querySelector(".search-input");
    const button = container.querySelector(".search-btn");

    if (!input || !button) {
      return;
    }

    input.setAttribute("aria-label", "Pesquisar nesta página");
    let highlighted = null;

    const clearHighlight = () => {
      highlighted?.classList.remove("site-search-highlight");
      highlighted = null;
    };

    const runSearch = () => {
      clearHighlight();
      input.setCustomValidity("");

      const term = input.value.trim().toLocaleLowerCase("pt-BR");
      if (!term) {
        input.setCustomValidity("Digite um termo para pesquisar.");
        input.reportValidity();
        return;
      }

      const candidates = Array.from(
        document.querySelectorAll("h1, h2, h3, p, td, th, label, button, a, span")
      );

      const match = candidates.find((element) => {
        if (element.closest(".search") || element.offsetParent === null) {
          return false;
        }

        return element.textContent
          .trim()
          .toLocaleLowerCase("pt-BR")
          .includes(term);
      });

      if (!match) {
        input.setCustomValidity("Nenhum resultado encontrado nesta página.");
        input.reportValidity();
        return;
      }

      highlighted = match;
      highlighted.classList.add("site-search-highlight");
      highlighted.scrollIntoView({ behavior: "smooth", block: "center" });
    };

    button.addEventListener("click", runSearch);
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        runSearch();
      }
    });
    input.addEventListener("input", () => {
      input.setCustomValidity("");
      clearHighlight();
    });
  });
})();
