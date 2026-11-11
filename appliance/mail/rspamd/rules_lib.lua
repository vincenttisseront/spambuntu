-- Spambuntu : moteur de règles de filtrage (fonctions pures, testables sans Rspamd : tests/lua/rules_lib_test.lua).
-- Doit rester équivalent à spambuntu_rules.py (evaluate / class_scores / in_list) : voir tests/data/rules_golden.json.
local M = {}

local function ip_from_string(text)
  local ok, rspamd_ip = pcall(require, "rspamd_ip")
  if not ok then return nil end
  local parsed, ip = pcall(rspamd_ip.from_string, text)
  if parsed then return ip end
  return nil
end

-- Score de spam 0-100 : marquage = 25, quarantaine = 50, rejet = 100 (interpolation linéaire entre les seuils).
function M.spam_score(raw, th)
  if raw <= 0 then return 0 end
  if raw >= th.reject then return 100 end
  local pts = { { 0, 0 }, { th.tag, 25 }, { th.quarantine, 50 }, { th.reject, 100 } }
  for i = 1, #pts - 1 do
    local x0, y0, x1, y1 = pts[i][1], pts[i][2], pts[i + 1][1], pts[i + 1][2]
    if raw < x1 then return math.floor(y0 + (raw - x0) / (x1 - x0) * (y1 - y0)) end
  end
  return 100
end

-- names : ensemble { NOM_DE_RÈGLE = true } ; signals : { classe = { {kind, name, points}, ... } }
function M.class_scores(names, signals, raw, th)
  local out = { spam = M.spam_score(raw, th) }
  for class, list in pairs(signals) do
    local total = 0
    for _, s in ipairs(list) do
      if s.kind == "exact" then
        if names[s.name] then total = total + s.points end
      else
        for name in pairs(names) do
          if name:find(s.name, 1, true) then total = total + s.points; break end
        end
      end
    end
    out[class] = math.min(100, total)
  end
  return out
end

local function is_ip_entry(entry)
  return entry:find(":", 1, true) ~= nil or entry:match("^%d+%.%d+%.%d+%.%d+/?%d*$") ~= nil
end

-- Prépare une liste d'entrées (adresses, domaines, réseaux IP) pour des recherches rapides.
function M.compile_list(entries)
  local list = { exact = {}, domains = {}, nets = {} }
  for _, entry in ipairs(entries or {}) do
    if entry:find("@", 1, true) then
      list.exact[entry] = true
    elseif is_ip_entry(entry) then
      local base, len = entry:match("^(.-)/(%d+)$")
      local ip = ip_from_string(base or entry)
      if ip then
        list.nets[#list.nets + 1] = { ip = ip, version = ip:get_version(), mask = tonumber(len) or (ip:get_version() == 4 and 32 or 128) }
      end
    else
      list.domains[entry] = true
    end
  end
  return list
end

local function domain_chain(addr)
  local domain = addr:match("@(.+)$") or ""
  local labels = {}
  for label in domain:gmatch("[^.]+") do labels[#labels + 1] = label end
  local chain = {}
  for i = 1, #labels - 1 do chain[#chain + 1] = table.concat(labels, ".", i) end
  return chain
end

function M.in_list(list, addrs, ip_text)
  for _, addr in ipairs(addrs or {}) do
    if addr ~= "" then
      if list.exact[addr] then return true end
      for _, d in ipairs(domain_chain(addr)) do
        if list.domains[d] then return true end
      end
    end
  end
  if ip_text and ip_text ~= "" and #list.nets > 0 then
    local client = ip_from_string(ip_text)
    if client then
      for _, net in ipairs(list.nets) do
        if net.version == client:get_version() and tostring(client:apply_mask(net.mask)) == tostring(net.ip:apply_mask(net.mask)) then
          return true
        end
      end
    end
  end
  return false
end

local function aligned(a, b)
  if a == "" or b == "" then return false end
  if a == b then return true end
  return a:sub(-(#b + 1)) == "." .. b or b:sub(-(#a + 1)) == "." .. a
end

-- in : { names = {ensemble}, raw, mime_from, env_from, rcpts = {...}, ip } ; conf : configuration rendue (spambuntu-rules.json)
function M.build_context(input, conf, lists)
  local mime_from, env_from = (input.mime_from or ""):lower(), (input.env_from or ""):lower()
  local from_domain, env_domain = mime_from:match("@(.+)$") or "", env_from:match("@(.+)$") or ""
  local names = input.names
  local authenticated = names.DMARC_POLICY_ALLOW or (names.R_SPF_ALLOW and aligned(from_domain, env_domain))
  local senders = {}
  if mime_from ~= "" then senders[#senders + 1] = mime_from end
  if env_from ~= "" then senders[#senders + 1] = env_from end
  local rcpts = {}
  for _, r in ipairs(input.rcpts or {}) do rcpts[#rcpts + 1] = r:lower() end
  return {
    scores = M.class_scores(names, conf.signals, input.raw, conf.thresholds), raw = input.raw, symbols = names,
    blocklist = M.in_list(lists.block, { mime_from, env_from }, input.ip) and true or false,
    safelist = (M.in_list(lists.safe, {}, input.ip) or (authenticated and M.in_list(lists.safe, { mime_from }, "") or false)) and true or false,
    dmarc_reject = names.DMARC_POLICY_REJECT and true or false,
    senders = senders, recipients = rcpts,
  }
end

function M.condition_matches(cond, ctx)
  local field, op, value = cond.field, cond.op, cond.value
  if ctx.scores[field] ~= nil then
    if op == ">=" then return ctx.scores[field] >= value end
    return ctx.scores[field] <= value
  end
  if field == "score" then
    if op == ">=" then return ctx.raw >= value end
    return ctx.raw <= value
  end
  if field == "blocklist" or field == "safelist" or field == "dmarc_reject" then
    return (ctx[field] and true or false) == value
  end
  if field == "symbol" then
    return (ctx.symbols[value] and true or false) == (op == "present")
  end
  local values = field == "sender" and ctx.senders or ctx.recipients
  for _, v in ipairs(values) do
    if op == "contains" and v:find(value, 1, true) then return true end
    if op == "equals" and v == value then return true end
    if op == "ends_with" and #v >= #value and v:sub(-#value) == value then return true end
  end
  return false
end

-- Retourne { matched = {règles satisfaites}, final = règle qui décide ou nil }
function M.evaluate(rules, ctx)
  local matched, final = {}, nil
  for _, rule in ipairs(rules) do
    if rule.enabled ~= false then      -- la configuration rendue ne contient que des règles actives
      local all, any = true, false
      for _, cond in ipairs(rule.conditions) do
        if M.condition_matches(cond, ctx) then any = true else all = false end
      end
      if (rule.match == "any" and any) or (rule.match ~= "any" and all) then
        matched[#matched + 1] = rule
        if rule.disposition ~= "continue" then final = rule; break end
      end
    end
  end
  return { matched = matched, final = final }
end

-- Action Rspamd correspondant à la disposition d'une règle.
function M.rspamd_action(rule, quarantine_enabled)
  local d = rule.disposition
  if d == "deliver" then return "no action" end
  if d == "tag" then return "add header" end
  if d == "reject" then return "reject" end
  if d == "quarantine" then return quarantine_enabled and "quarantine" or "add header" end
  return nil
end

local CLASS_ORDER = { "spam", "malware", "phish", "impostor", "bulk" }
M.CLASS_ORDER = CLASS_ORDER

function M.scores_text(scores, sep)
  local parts = {}
  for _, class in ipairs(CLASS_ORDER) do parts[#parts + 1] = class .. ":" .. tostring(scores[class] or 0) end
  return table.concat(parts, sep or ";")
end

return M
