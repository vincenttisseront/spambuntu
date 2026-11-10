/* Page « Mises à jour » : recherche, installation, suivi de progression.
   Aucun contenu distant n'est injecté en HTML : tout passe par textContent (notes de release comprises). */
(() => {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const $ = (id) => document.getElementById(id);
  const BUSY = new Set(["queued", "running"]);
  const LABELS = { queued: "en attente", running: "en cours", success: "terminée", failed: "échec", rolled_back: "annulée" };
  const GIVE_UP_WAITING_MS = 90_000;
  const MAX_MISSES = 90;

  let last = null;        // dernier statut reçu
  let expecting = false;  // une opération a été demandée (ou détectée) et son issue n'est pas encore connue
  let baseline = "";      // started_at de la dernière opération connue avant la demande
  let expectSince = 0;
  let misses = 0;
  let timer = null;

  async function api(path, method = "GET", body) {
    const res = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 401) {
      location.href = "/login";
      throw new Error("Session expirée");
    }
    let data = {};
    try { data = await res.json(); } catch (_) { /* corps vide */ }
    if (!res.ok) throw new Error(data.error || `Erreur HTTP ${res.status}`);
    return data;
  }

  function banner(kind, text) {
    const el = $("banner");
    if (!text) { el.hidden = true; return; }
    el.className = `banner ${kind}`;
    el.textContent = text;
    el.hidden = false;
  }

  const isNewRun = (apply) =>
    !!apply && (apply.state === "queued" || (apply.started_at && apply.started_at > baseline));

  function formatDate(iso) {
    const d = iso ? new Date(iso) : null;
    return d && !Number.isNaN(d.getTime()) ? d.toLocaleString("fr-FR") : "";
  }

  function render(s) {
    last = s;
    const apply = s.apply;
    const running = !!apply && BUSY.has(apply.state);

    if (running && !expecting) { // page ouverte pendant une opération déjà en cours
      expecting = true;
      baseline = "";
      expectSince = Date.now();
    }
    const waiting = expecting && !isNewRun(apply);
    const inProgress = running || waiting;

    $("current").textContent = s.current;
    $("checked-at").textContent = formatDate(s.check.checked_at) || "jamais";
    const err = $("check-error");
    err.hidden = !s.check.error;
    err.textContent = s.check.error ? `Dernière recherche en erreur : ${s.check.error}` : "";

    const latest = s.check.latest;
    const showLatest = !!(s.check.update_available && latest);
    $("latest-card").hidden = !showLatest;
    if (showLatest) {
      $("latest-version").textContent = latest.version;
      $("latest-pre").hidden = !latest.prerelease;
      const size = latest.size
        ? ` · ${latest.size < 1048576 ? `${Math.max(1, Math.round(latest.size / 1024))} Ko` : `${(latest.size / 1048576).toFixed(1)} Mo`}`
        : "";
      $("latest-meta").textContent = `Publiée le ${formatDate(latest.published_at)}${size}`;
      $("latest-notes").textContent = latest.notes || "Aucune note de version.";
    }
    $("btn-rollback").hidden = !s.can_rollback;
    for (const id of ["btn-check", "btn-apply", "btn-rollback"]) $(id).disabled = inProgress;

    $("progress-card").hidden = !(expecting || inProgress);
    if (!$("progress-card").hidden) {
      const shown = waiting ? { state: "queued", percent: 0, message: "Demande envoyée…" } : apply;
      $("state-label").textContent = LABELS[shown.state] || shown.state;
      $("progress").value = shown.percent || 0;
      $("progress-message").textContent = shown.message || "";
      const log = $("log");
      log.textContent = (s.log || []).join("\n");
      log.scrollTop = log.scrollHeight;
    }

    if (expecting && waiting && Date.now() - expectSince > GIVE_UP_WAITING_MS) {
      expecting = false;
      banner("error", "L'opération ne s'est pas lancée. Consultez le journal du système.");
      return false;
    }
    if (expecting && isNewRun(apply) && !BUSY.has(apply.state)) { // issue connue
      expecting = false;
      if (apply.state === "success") {
        banner("success", `${apply.message}. La page va se recharger…`);
        setTimeout(() => location.reload(), 2000);
      } else {
        banner(apply.state === "rolled_back" ? "warning" : "error", apply.message);
      }
      return false;
    }
    if (!inProgress && !expecting && s.running_version !== s.current) {
      banner("warning", `La console tourne encore en version ${s.running_version} alors que la version ${s.current} est installée : redémarrez le service spambuntu-webui.`);
    }
    return inProgress || expecting;
  }

  async function refresh() {
    clearTimeout(timer);
    try {
      const status = await api("/api/update/status");
      misses = 0;
      if (render(status)) timer = setTimeout(refresh, 1500);
    } catch (exc) {
      if (!expecting) { banner("error", exc.message); return; }
      misses += 1; // la console redémarre pendant la mise à jour : c'est normal, on réessaie
      $("progress-message").textContent = "La console redémarre, reconnexion en cours…";
      if (misses > MAX_MISSES) {
        expecting = false;
        banner("error", "La console ne répond plus. Vérifiez l'appliance (systemctl status spambuntu-webui).");
        return;
      }
      timer = setTimeout(refresh, 2000);
    }
  }

  function startExpecting() {
    baseline = (last && last.apply && last.apply.started_at) || "";
    expecting = true;
    expectSince = Date.now();
    banner(null);
  }

  $("btn-check").addEventListener("click", async () => {
    banner(null);
    $("btn-check").disabled = true;
    try {
      render(await api("/api/update/check", "POST"));
    } catch (exc) {
      banner("error", exc.message);
    } finally {
      if (last) render(last);
    }
  });

  $("btn-apply").addEventListener("click", async () => {
    const version = last && last.check.latest && last.check.latest.version;
    if (!version) return;
    if (!confirm(`Installer la version ${version} ?\n\nLa console sera brièvement indisponible pendant le redémarrage.`)) return;
    startExpecting();
    try {
      await api("/api/update/apply", "POST", { version });
    } catch (exc) {
      expecting = false;
      banner("error", exc.message);
      render(last);
      return;
    }
    refresh();
  });

  $("btn-rollback").addEventListener("click", async () => {
    if (!confirm("Revenir à la version précédente ?\n\nLes données et la configuration actuelles sont conservées.")) return;
    startExpecting();
    try {
      await api("/api/update/rollback", "POST");
    } catch (exc) {
      expecting = false;
      banner("error", exc.message);
      render(last);
      return;
    }
    refresh();
  });

  refresh();
})();
