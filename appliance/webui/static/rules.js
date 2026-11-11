// Page « Règles » : confirmation avant suppression, et adaptation du formulaire d'une règle
// (opérateurs et valeur selon le champ, dossier de quarantaine selon l'action). Sans ce script, le formulaire reste
// utilisable : le serveur valide tout.
(function () {
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) event.preventDefault();
    });
  });

  var ruleForm = document.querySelector("form[data-rule-form]");
  if (!ruleForm) return;

  function refreshCondition(row) {
    var field = row.querySelector("[data-field]");
    var op = row.querySelector("[data-op]");
    var value = row.querySelector("[data-value]");
    var kind = field.options[field.selectedIndex] ? field.options[field.selectedIndex].getAttribute("data-kind") : "";
    var any = false;
    Array.prototype.forEach.call(op.options, function (option) {
      var ok = option.value === "" || option.getAttribute("data-kind") === kind;
      option.hidden = !ok;
      option.disabled = !ok;
      if (ok && option.value) any = true;
    });
    var current = op.options[op.selectedIndex];
    if (!current || current.disabled || (kind && !current.value)) {
      for (var i = 0; i < op.options.length; i++) {
        if (!op.options[i].disabled && op.options[i].value) { op.selectedIndex = i; break; }
      }
    }
    var chosen = op.options[op.selectedIndex];
    var isBool = kind === "bool";
    value.classList.toggle("no-value", isBool);
    value.disabled = isBool;
    value.type = kind === "number" ? "number" : "text";
    value.step = kind === "number" ? "any" : "";
    value.setAttribute("list", kind === "symbol" ? "known-symbols" : "");
    value.placeholder = { number: "0 – 100", symbol: "MIME_BAD_EXTENSION", text: "paypal.com" }[kind] || "";
    row.classList.toggle("empty", !kind);
    return any;
  }

  ruleForm.querySelectorAll(".cond-row").forEach(function (row) {
    row.querySelector("[data-field]").addEventListener("change", function () { refreshCondition(row); });
    refreshCondition(row);
  });

  // Lignes vides repliées : on n'affiche que les lignes utilisées plus une, et un bouton pour en ajouter.
  ruleForm.querySelectorAll("fieldset[data-grow]").forEach(function (group) {
    var rows = Array.prototype.slice.call(group.children);
    function isEmpty(row) {
      return Array.prototype.every.call(row.querySelectorAll("input, select"), function (el) { return !el.value; });
    }
    var shown = 1;
    rows.forEach(function (row, i) { if (!isEmpty(row)) shown = Math.max(shown, i + 1); });
    var button = document.createElement("button");
    button.type = "button";
    button.className = "small-btn";
    button.textContent = group.getAttribute("data-grow");
    function refresh() {
      rows.forEach(function (row, i) { row.hidden = i >= shown; });
      button.hidden = shown >= rows.length;
    }
    button.addEventListener("click", function () { shown = Math.min(shown + 1, rows.length); refresh(); });
    group.insertAdjacentElement("afterend", button);
    refresh();
  });

  var disposition = ruleForm.querySelector("[name=disposition]");
  var folder = ruleForm.querySelector(".folder-block");
  function refreshDisposition() { if (folder) folder.hidden = disposition.value !== "quarantine"; }
  if (disposition) { disposition.addEventListener("change", refreshDisposition); refreshDisposition(); }
})();
