-- Spambuntu : protection contre l'usurpation d'identité (dirigeants, domaines imitateurs, homoglyphes) et courrier « image seule ».
-- Chargé par Rspamd (rspamd.local.lua) ; la configuration est écrite par spambuntu-mail dans spambuntu-identity.json.
local ucl = require "ucl"
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"

local LIB_PATH = "/etc/rspamd/spambuntu/identity_lib.lua"
local CONF_PATH = "/etc/rspamd/local.d/spambuntu-identity.json"

local ok, lib = pcall(dofile, LIB_PATH)
if not ok or type(lib) ~= "table" then
  rspamd_logger.errx(rspamd_config, "spambuntu_identity : bibliothèque illisible (%s), règles désactivées", LIB_PATH)
  return
end

local conf = { domains = {}, vip = {}, brands = {}, score_identity = 8.0, score_brand = 2.5, score_image = 2.0 }
local parser = ucl.parser()
local parsed = parser:parse_file(CONF_PATH)
if parsed then
  local obj = parser:get_object()
  if type(obj) == "table" then
    for _, key in ipairs({ "domains", "vip", "brands" }) do
      if type(obj[key]) == "table" then conf[key] = obj[key] end
    end
    for _, key in ipairs({ "score_identity", "score_brand", "score_image" }) do
      if tonumber(obj[key]) then conf[key] = tonumber(obj[key]) end
    end
  end
end

local function is_internal(task)
  if task:get_user() then return true end
  local ip = task:get_from_ip()
  return ip and ip:is_valid() and ip:is_local()
end

local function clean(value)
  return (tostring(value or ""):gsub("[%[%];,%s]+", "_"):sub(1, 80))
end

-- Adresses d'expéditeur : en-tête From, puis Reply-To.
local function from_address(task)
  local from = task:get_from("mime")
  if from and from[1] then return from[1] end
  return nil
end

local function reply_to_domain(task)
  local header = task:get_header("Reply-To")
  if not header then return nil end
  return tostring(header):match("@([%w%.%-]+)%f[^%w%.%-]")
end

-- Domaines de l'expéditeur (From puis Reply-To) comparés aux domaines protégés.
local function domain_findings(task)
  local findings = {}
  local protected = { own = conf.domains, brands = conf.brands }
  local from = from_address(task)
  local seen = {}
  for _, d in ipairs({ from and from.domain or "", reply_to_domain(task) or "" }) do
    d = tostring(d):lower()
    if d ~= "" and not seen[d] then
      seen[d] = true
      local r = lib.analyze_domain(d, protected)
      if r then r.domain = d; findings[#findings + 1] = r end
    end
  end
  return findings
end

local function first_of(findings, kinds)
  for _, f in ipairs(findings) do
    if kinds[f.kind] then return f end
  end
  return nil
end

local SYMBOLS = {
  SPAMBUNTU_VIP_SPOOF = { score = conf.score_identity, description = "Nom d'affichage d'un dirigeant protégé utilisé depuis une autre adresse" },
  SPAMBUNTU_LOOKALIKE = { score = conf.score_identity, description = "Domaine expéditeur imitant le vôtre ou celui d'une marque" },
  SPAMBUNTU_IDN_HOMOGLYPH = { score = conf.score_identity, description = "Domaine expéditeur mêlant des lettres d'alphabets différents d'apparence identique" },
  SPAMBUNTU_BRAND_IN_DOMAIN = { score = conf.score_brand, description = "Nom d'une marque ou de votre domaine dans un domaine expéditeur différent" },
}

-- Une seule évaluation : le symbole le plus grave pèse, les autres sont posés à 0 (ils restent visibles pour l'analyse).
-- Une heuristique d'identité ne peut donc jamais, en se cumulant avec elle-même, amener seule un message au rejet.
local identity_id = rspamd_config:register_symbol({
  name = "SPAMBUNTU_IDENTITY",
  type = "callback",
  score = 0.0,
  callback = function(task)
    if is_internal(task) then return false end
    local hits = {}
    local from = from_address(task)
    if from and #conf.vip > 0 then
      local name = lib.vip_spoof(from.name, from.addr, from.domain, conf.vip, conf.domains)
      if name then hits[#hits + 1] = { "SPAMBUNTU_VIP_SPOOF", clean(name) } end
    end
    local findings = domain_findings(task)
    local f = first_of(findings, { lookalike = true, tld_swap = true })
    if f then hits[#hits + 1] = { "SPAMBUNTU_LOOKALIKE", clean(f.domain .. "~" .. f.target) } end
    f = first_of(findings, { homoglyph = true })
    if f then hits[#hits + 1] = { "SPAMBUNTU_IDN_HOMOGLYPH", clean(f.domain) } end
    f = first_of(findings, { brand_in_domain = true })
    if f then hits[#hits + 1] = { "SPAMBUNTU_BRAND_IN_DOMAIN", clean(f.domain .. "~" .. f.target) } end
    -- Ordre de gravité décroissante : l'identité usurpée, puis le domaine imitateur, puis l'indice faible.
    local strongest = true
    for _, hit in ipairs(hits) do
      task:insert_result(hit[1], strongest and 1.0 or 0.0, hit[2])
      strongest = false
    end
  end,
})
for name, def in pairs(SYMBOLS) do
  rspamd_config:register_symbol({ name = name, type = "virtual", parent = identity_id, score = def.score, description = def.description })
end

-- Courrier composé presque uniquement d'images : technique classique pour cacher des mots-clés aux filtres de texte.
rspamd_config.SPAMBUNTU_IMAGE_ONLY = {
  score = conf.score_image,
  description = "Message presque sans texte, composé d'images",
  callback = function(task)
    local images, words = 0, 0
    for _, part in ipairs(task:get_text_parts() or {}) do
      words = words + (part:get_words_count() or 0)
      local html = part:get_html()
      if html then
        local imgs = html:get_images()
        if imgs then images = images + #imgs end
      end
    end
    if images >= 1 and words < 12 then return true, 1.0, tostring(images) .. " image(s)" end
    return false
  end,
}

lua_util.debugm("spambuntu_identity", rspamd_config, "règles d'identité chargées : %s dirigeants, %s marques",
  #conf.vip, #conf.brands)
