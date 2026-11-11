-- Spambuntu : règles de filtrage ordonnées (post-filtre). Chargé par Rspamd (rspamd.local.lua) ; la configuration
-- (règles, listes, signaux) est écrite par spambuntu-mail dans spambuntu-rules.json.
--
-- Le post-filtre s'exécute APRÈS l'analyse IA (priorité 20 > 9) : il voit donc toutes les règles déclenchées. Il fixe
-- l'action finale (livrer, marquer, quarantaine, rejeter) et ajoute les en-têtes de la règle retenue. Sans configuration
-- lisible, il ne fait rien : les seuils de score de Rspamd restent alors seuls juges (repli sûr).
local ucl = require "ucl"
local rspamd_logger = require "rspamd_logger"

local LIB_PATH = "/etc/rspamd/spambuntu/rules_lib.lua"
local CONF_PATH = "/etc/rspamd/local.d/spambuntu-rules.json"
local REJECT_MESSAGE = "Message refused by security policy"

local ok, lib = pcall(dofile, LIB_PATH)
if not ok or type(lib) ~= "table" then
  rspamd_logger.errx(rspamd_config, "spambuntu_rules : bibliothèque illisible (%s), règles désactivées", LIB_PATH)
  return
end

local parser = ucl.parser()
if not parser:parse_file(CONF_PATH) then
  rspamd_logger.errx(rspamd_config, "spambuntu_rules : configuration illisible (%s), règles désactivées", CONF_PATH)
  return
end
local conf = parser:get_object()
if type(conf) ~= "table" or conf.enabled == false or type(conf.rules) ~= "table" or type(conf.thresholds) ~= "table" then
  return
end
local lists = {
  block = lib.compile_list((conf.lists or {}).block),
  safe = lib.compile_list((conf.lists or {}).safe),
}

local function is_internal(task)
  if task:get_user() then return true end
  local ip = task:get_from_ip()
  return ip and ip:is_valid() and ip:is_local()
end

local function addresses(list)
  local out = {}
  for _, a in ipairs(list or {}) do
    if a.addr and a.addr ~= "" then out[#out + 1] = a.addr end
  end
  return out
end

local function evaluate(task)
  if is_internal(task) or task:has_pre_result() then return end
  local names = {}
  for _, sym in ipairs(task:get_symbols_all() or {}) do
    if sym.name ~= "SPAMBUNTU_RULE" then names[sym.name] = true end
  end
  local ip = task:get_from_ip()
  local mime_from = addresses(task:get_from("mime"))[1] or ""
  local env_from = addresses(task:get_from("smtp"))[1] or ""
  local ctx = lib.build_context({
    names = names, raw = task:get_metric_score()[1], mime_from = mime_from, env_from = env_from,
    rcpts = addresses(task:get_recipients("smtp")), ip = (ip and ip:is_valid()) and tostring(ip) or "",
  }, conf, lists)

  local result = lib.evaluate(conf.rules, ctx)
  -- Les en-têtes X-Spambuntu-* envoyés par l'expéditeur ne sont jamais conservés : seuls les nôtres font foi.
  local add, remove = {}, { ["X-Spambuntu-Rule"] = 0, ["X-Spambuntu-Scores"] = 0 }
  for _, rule in ipairs(result.matched) do
    for _, header in ipairs(rule.headers or {}) do
      add[header.name] = header.value
      remove[header.name] = 0
    end
  end
  local final = result.final
  if final then
    if final.explain then
      add["X-Spambuntu-Rule"] = final.id
      add["X-Spambuntu-Scores"] = lib.scores_text(ctx.scores, " ")
    end
    local quarantined = final.disposition == "quarantine" and conf.quarantine_enabled
    local opts = { final.id, quarantined and final.folder or "-", quarantined and (final.access or "admin") or "-" }
    for _, class in ipairs(lib.CLASS_ORDER) do opts[#opts + 1] = class .. ":" .. tostring(ctx.scores[class] or 0) end
    task:insert_result("SPAMBUNTU_RULE", 0.0, unpack(opts))
    local action = lib.rspamd_action(final, conf.quarantine_enabled)
    if action then
      task:set_pre_result(action, action == "reject" and REJECT_MESSAGE or final.id, "spambuntu_rules")
    end
  end
  task:set_milter_reply({ add_headers = add, remove_headers = remove })
end

local id = rspamd_config:register_symbol({
  name = "SPAMBUNTU_RULES",
  type = "postfilter",
  priority = 20,
  flags = "nostat",
  callback = function(task)
    local good, err = pcall(evaluate, task)
    if not good then rspamd_logger.errx(task, "spambuntu_rules : évaluation impossible (%s)", err) end
  end,
})
rspamd_config:register_symbol({
  name = "SPAMBUNTU_RULE", type = "virtual", parent = id, score = 0.0,
  description = "Règle de filtrage appliquée (identifiant, dossier, accès, scores par classe)",
})
rspamd_logger.infox(rspamd_config, "spambuntu_rules : %s règles actives", #conf.rules)
