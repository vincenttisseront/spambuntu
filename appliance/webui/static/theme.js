/* Thème clair / sombre : mémorisé par navigateur (facultatif : la page fonctionne sans stockage). */
(() => {
  "use strict";
  const root = document.documentElement;
  const KEY = "spambuntu-theme";
  const read = () => { try { return localStorage.getItem(KEY); } catch (e) { return null; } };
  const write = (v) => { try { localStorage.setItem(KEY, v); } catch (e) { /* stockage indisponible */ } };
  const apply = (v) => { if (v === "dark" || v === "light") root.setAttribute("data-theme", v); };
  apply(read());
  document.addEventListener("DOMContentLoaded", () => {
    for (const btn of document.querySelectorAll("[data-theme-toggle]")) {
      btn.addEventListener("click", () => {
        const dark = root.getAttribute("data-theme") === "dark" ||
          (!root.getAttribute("data-theme") && window.matchMedia("(prefers-color-scheme: dark)").matches);
        const next = dark ? "light" : "dark";
        apply(next);
        write(next);
      });
    }
  });
})();
