// Sélection multiple des listes : « tout sélectionner » et activation des boutons de lot (aucune donnée n'est envoyée d'ici).
(function () {
  document.querySelectorAll("form[data-bulk]").forEach(function (form) {
    var rows = Array.prototype.slice.call(form.querySelectorAll("input[data-row]"));
    var all = form.querySelector("input[data-select-all]");
    var counter = form.querySelector("[data-selected]");
    var buttons = form.querySelectorAll("[data-needs-selection]");
    function refresh() {
      var n = rows.filter(function (r) { return r.checked; }).length;
      if (counter) counter.textContent = String(n);
      buttons.forEach(function (b) { b.disabled = n === 0; });
      if (all) { all.checked = n > 0 && n === rows.length; all.indeterminate = n > 0 && n < rows.length; all.disabled = rows.length === 0; }
    }
    rows.forEach(function (r) { r.addEventListener("change", refresh); });
    if (all) all.addEventListener("change", function () { rows.forEach(function (r) { r.checked = all.checked; }); refresh(); });
    refresh();
  });
})();
