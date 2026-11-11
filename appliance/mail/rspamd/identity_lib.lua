-- Spambuntu : fonctions pures de détection d'usurpation d'identité (noms d'affichage, domaines imitateurs, homoglyphes).
-- Aucune dépendance à Rspamd : ce fichier est testé seul (rspamadm lua) puis chargé par la règle spambuntu_identity.lua.
local M = {}

-- ------------------------------------------------------------------ UTF-8 et normalisation

local ACCENTS = {
  ["à"] = "a", ["á"] = "a", ["â"] = "a", ["ä"] = "a", ["ã"] = "a", ["å"] = "a", ["À"] = "a", ["Á"] = "a", ["Â"] = "a", ["Ä"] = "a", ["Ã"] = "a", ["Å"] = "a",
  ["è"] = "e", ["é"] = "e", ["ê"] = "e", ["ë"] = "e", ["È"] = "e", ["É"] = "e", ["Ê"] = "e", ["Ë"] = "e",
  ["ì"] = "i", ["í"] = "i", ["î"] = "i", ["ï"] = "i", ["Ì"] = "i", ["Í"] = "i", ["Î"] = "i", ["Ï"] = "i",
  ["ò"] = "o", ["ó"] = "o", ["ô"] = "o", ["ö"] = "o", ["õ"] = "o", ["Ò"] = "o", ["Ó"] = "o", ["Ô"] = "o", ["Ö"] = "o", ["Õ"] = "o",
  ["ù"] = "u", ["ú"] = "u", ["û"] = "u", ["ü"] = "u", ["Ù"] = "u", ["Ú"] = "u", ["Û"] = "u", ["Ü"] = "u",
  ["ý"] = "y", ["ÿ"] = "y", ["Ý"] = "y", ["ç"] = "c", ["Ç"] = "c", ["ñ"] = "n", ["Ñ"] = "n",
  ["ß"] = "ss", ["æ"] = "ae", ["Æ"] = "ae", ["œ"] = "oe", ["Œ"] = "oe",
}

-- Lettres cyrilliques, grecques et arméniennes qui ressemblent à une lettre latine (point de code -> lettre latine).
local CONFUSABLE = {
  [0x0430] = "a", [0x0435] = "e", [0x043E] = "o", [0x0440] = "p", [0x0441] = "c", [0x0443] = "y", [0x0445] = "x",
  [0x0455] = "s", [0x0456] = "i", [0x0458] = "j", [0x04CF] = "l", [0x043A] = "k", [0x04BB] = "h", [0x0501] = "d",
  [0x051B] = "q", [0x051D] = "w", [0x0475] = "v", [0x044C] = "b",
  [0x0410] = "a", [0x0412] = "b", [0x0415] = "e", [0x041A] = "k", [0x041C] = "m", [0x041D] = "h", [0x041E] = "o",
  [0x0420] = "p", [0x0421] = "c", [0x0422] = "t", [0x0425] = "x", [0x0406] = "i", [0x0408] = "j", [0x0405] = "s",
  [0x03B1] = "a", [0x03BF] = "o", [0x03C1] = "p", [0x03BD] = "v", [0x03B9] = "i", [0x03BA] = "k", [0x03C5] = "u",
  [0x0391] = "a", [0x0392] = "b", [0x0395] = "e", [0x0396] = "z", [0x0397] = "h", [0x0399] = "i", [0x039A] = "k",
  [0x039C] = "m", [0x039D] = "n", [0x039F] = "o", [0x03A1] = "p", [0x03A4] = "t", [0x03A5] = "y", [0x03A7] = "x",
  [0x0585] = "o", [0x057D] = "u", [0x0570] = "h",
}

local function is_foreign_script(cp)
  return (cp >= 0x0370 and cp <= 0x03FF) or (cp >= 0x0400 and cp <= 0x052F) or (cp >= 0x0530 and cp <= 0x058F)
end

-- Découpe en points de code ; octets invalides ignorés.
local function codepoints(s)
  local out, i, n = {}, 1, #s
  while i <= n do
    local c = s:byte(i)
    local cp, len
    if c < 0x80 then cp, len = c, 1
    elseif c >= 0xC2 and c < 0xE0 then cp, len = c % 0x20, 2
    elseif c >= 0xE0 and c < 0xF0 then cp, len = c % 0x10, 3
    elseif c >= 0xF0 and c < 0xF5 then cp, len = c % 0x08, 4
    else i = i + 1; goto continue end
    do
      local ok = i + len - 1 <= n
      if ok then
        for k = 1, len - 1 do
          local b = s:byte(i + k)
          if not b or b < 0x80 or b >= 0xC0 then ok = false; break end
          cp = cp * 64 + (b % 64)
        end
      end
      if ok then out[#out + 1] = cp; i = i + len else i = i + 1 end
    end
    ::continue::
  end
  return out
end
M.codepoints = codepoints

local function utf8_char(cp)
  if cp < 0x80 then return string.char(cp) end
  if cp < 0x800 then return string.char(0xC0 + math.floor(cp / 64), 0x80 + cp % 64) end
  if cp < 0x10000 then
    return string.char(0xE0 + math.floor(cp / 4096), 0x80 + math.floor(cp / 64) % 64, 0x80 + cp % 64)
  end
  return string.char(0xF0 + math.floor(cp / 262144), 0x80 + math.floor(cp / 4096) % 64, 0x80 + math.floor(cp / 64) % 64, 0x80 + cp % 64)
end

-- Minuscules, sans accents ni ponctuation, espaces simples : « Jean-Éric  DUPONT (PDG) » -> « jean eric dupont pdg ».
function M.normalize_name(s)
  if type(s) ~= "string" then return "" end
  s = s:sub(1, 200)
  local out = {}
  for _, cp in ipairs(codepoints(s)) do
    local ch = utf8_char(cp)
    local mapped = ACCENTS[ch]
    if mapped then out[#out + 1] = mapped
    elseif CONFUSABLE[cp] then out[#out + 1] = CONFUSABLE[cp]
    elseif cp < 0x80 then out[#out + 1] = ch:lower()
    else out[#out + 1] = " " end
  end
  local flat = table.concat(out):gsub("[^%w]+", " ")
  return (flat:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function words(norm)
  local t = {}
  for w in norm:gmatch("%S+") do t[#t + 1] = w end
  return t
end

-- Le nom d'affichage désigne-t-il ce dirigeant ? Tous les mots du nom protégé (au moins deux) doivent figurer dans le nom
-- d'affichage (ordre indifférent : « Dupont, Jean (PDG) ») ; un nom protégé d'un seul mot doit être le nom complet.
function M.display_matches(display, vip_name)
  local d, v = words(M.normalize_name(display)), words(M.normalize_name(vip_name))
  if #v == 0 or #d == 0 then return false end
  if #v == 1 then return #d == 1 and d[1] == v[1] end
  local present = {}
  for _, w in ipairs(d) do present[w] = true end
  for _, w in ipairs(v) do
    if not present[w] then return false end
  end
  return true
end

-- ------------------------------------------------------------------ domaines

local SECOND_LEVEL = { co = true, com = true, org = true, net = true, gov = true, ac = true, edu = true, ltd = true }
-- Suffixes publics à plusieurs étiquettes les plus courants (le calcul complet du TLD n'est pas disponible hors d'un worker Rspamd).
local MULTI_SUFFIX = {}
for _, suffix in ipairs({ "gouv.fr", "asso.fr", "com.fr", "nom.fr", "gouv.qc.ca", "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk",
                          "ltd.uk", "plc.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "co.jp", "ne.jp",
                          "or.jp", "co.za", "com.br", "com.cn", "com.tr", "com.mx", "co.in", "co.kr" }) do
  MULTI_SUFFIX[suffix] = true
end

-- (domaine enregistrable, étiquette, suffixe).
function M.split_domain(domain)
  domain = tostring(domain or ""):lower():gsub("%.$", "")
  local labels = {}
  for l in domain:gmatch("[^.]+") do labels[#labels + 1] = l end
  local n = #labels
  if n < 2 then return domain, domain, "" end
  local take = 2
  if n >= 3 and (MULTI_SUFFIX[labels[n - 1] .. "." .. labels[n]] or (#labels[n] == 2 and SECOND_LEVEL[labels[n - 1]])) then take = 3 end
  local reg = table.concat(labels, ".", n - take + 1, n)
  return reg, labels[n - take + 1], table.concat(labels, ".", n - take + 2, n)
end

-- Décodage Punycode (RFC 3492) d'une étiquette « xn--… » ; retourne la chaîne UTF-8 ou nil.
local function punycode_decode(input)
  local base, tmin, tmax, skew, damp = 36, 1, 26, 38, 700
  local n, i, bias = 128, 0, 72
  local out = {}
  local pos = 1
  local delim = input:match(".*()%-")
  if delim and delim > 1 then
    for k = 1, delim - 1 do out[#out + 1] = input:byte(k) end
    pos = delim + 1
  end
  local function adapt(delta, numpoints, first)
    delta = first and math.floor(delta / damp) or math.floor(delta / 2)
    delta = delta + math.floor(delta / numpoints)
    local k = 0
    while delta > ((base - tmin) * tmax) / 2 do
      delta = math.floor(delta / (base - tmin))
      k = k + base
    end
    return k + math.floor((base - tmin + 1) * delta / (delta + skew))
  end
  while pos <= #input do
    local oldi, w, k = i, 1, base
    while true do
      if pos > #input then return nil end
      local c = input:byte(pos); pos = pos + 1
      local digit
      if c >= 48 and c <= 57 then digit = c - 22 elseif c >= 65 and c <= 90 then digit = c - 65
      elseif c >= 97 and c <= 122 then digit = c - 97 else return nil end
      i = i + digit * w
      local t = k <= bias and tmin or (k >= bias + tmax and tmax or k - bias)
      if digit < t then break end
      w = w * (base - t)
      k = k + base
      if w > 1e9 then return nil end
    end
    bias = adapt(i - oldi, #out + 1, oldi == 0)
    n = n + math.floor(i / (#out + 1))
    i = i % (#out + 1)
    if n > 0x10FFFF then return nil end
    table.insert(out, i + 1, n)
    i = i + 1
  end
  local chars = {}
  for _, cp in ipairs(out) do chars[#chars + 1] = utf8_char(cp) end
  return table.concat(chars)
end
M.punycode_decode = punycode_decode

-- Le domaine avec ses étiquettes « xn-- » décodées.
function M.decode_domain(domain)
  local parts = {}
  for label in tostring(domain or ""):gmatch("[^.]+") do
    local decoded = label:lower():match("^xn%-%-(.+)$") and punycode_decode(label:lower():sub(5)) or nil
    parts[#parts + 1] = decoded or label
  end
  return table.concat(parts, ".")
end

-- Empreinte visuelle : deux chaînes qui se ressemblent à l'œil ont la même empreinte.
function M.skeleton(s)
  local out = {}
  for _, cp in ipairs(codepoints(tostring(s):sub(1, 120))) do
    local ch = utf8_char(cp)
    if ACCENTS[ch] then out[#out + 1] = ACCENTS[ch]
    elseif CONFUSABLE[cp] then out[#out + 1] = CONFUSABLE[cp]
    elseif cp < 0x80 then out[#out + 1] = ch:lower()
    else out[#out + 1] = "?" end
  end
  local t = table.concat(out):gsub("[%-_.]", "")
  t = t:gsub("rn", "m"):gsub("vv", "w"):gsub("cl", "d")
  t = t:gsub("0", "o"):gsub("1", "l"):gsub("i", "l"):gsub("3", "e"):gsub("4", "a"):gsub("5", "s"):gsub("7", "t")
  return t
end

-- Distance d'édition (insertion, suppression, substitution, transposition de deux lettres voisines).
function M.edit_distance(a, b, limit)
  local la, lb = #a, #b
  if math.abs(la - lb) > limit then return limit + 1 end
  local prev2, prev, cur = {}, {}, {}
  for j = 0, lb do prev[j] = j end
  for i = 1, la do
    cur = { [0] = i }
    local best = cur[0]
    for j = 1, lb do
      local cost = a:byte(i) == b:byte(j) and 0 or 1
      local v = math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
      if i > 1 and j > 1 and a:byte(i) == b:byte(j - 1) and a:byte(i - 1) == b:byte(j) then
        v = math.min(v, prev2[j - 2] + 1)
      end
      cur[j] = v
      if v < best then best = v end
    end
    if best > limit then return limit + 1 end
    prev2, prev = prev, cur
  end
  return prev[lb]
end

-- ------------------------------------------------------------------ analyse d'un domaine expéditeur

local function set_of(list)
  local s = {}
  for _, d in ipairs(list or {}) do s[tostring(d):lower()] = true end
  return s
end

-- Compare un domaine expéditeur aux domaines protégés. `protected` = {own = {...}, brands = {...}} (listes de domaines).
-- Retourne nil ou {kind = "lookalike" | "homoglyph" | "tld_swap" | "brand_in_domain", target = domaine protégé}.
function M.analyze_domain(domain, protected, split)
  split = split or M.split_domain
  local own, brands = set_of(protected.own), set_of(protected.brands)
  local decoded = M.decode_domain(domain)
  local reg_ascii = split(tostring(domain):lower())
  local reg, label, suffix = split(decoded)
  if own[reg] or brands[reg] or own[reg_ascii] or brands[reg_ascii] then return nil end

  -- Alphabets mélangés dans une même étiquette, ou étiquette entièrement composée de lettres qui imitent le latin.
  local cps = codepoints(label)
  local latin, foreign = 0, 0
  for _, cp in ipairs(cps) do
    if is_foreign_script(cp) then foreign = foreign + 1
    elseif (cp >= 0x61 and cp <= 0x7A) or (cp >= 0x30 and cp <= 0x39) then latin = latin + 1 end
  end

  local candidates = {}
  for _, d in ipairs(protected.own or {}) do candidates[#candidates + 1] = { domain = d:lower(), own = true } end
  for _, d in ipairs(protected.brands or {}) do candidates[#candidates + 1] = { domain = d:lower(), own = false } end

  local best
  local rank = { homoglyph = 4, lookalike = 3, tld_swap = 2, brand_in_domain = 1 }
  local function consider(kind, target)
    if not best or rank[kind] > rank[best.kind] then best = { kind = kind, target = target } end
  end

  local skel_label = M.skeleton(label)
  local tokens = {}
  for token in label:gmatch("[^%-_]+") do tokens[#tokens + 1] = token end

  for _, c in ipairs(candidates) do
    local _, plabel, psuffix = split(c.domain)
    local pskel = M.skeleton(plabel)
    local pn = #plabel
    if label == plabel and suffix ~= psuffix and c.own and pn >= 4 then
      consider("tld_swap", c.domain)
    elseif label ~= plabel then
      if foreign > 0 and pn >= 4 and skel_label == pskel then
        consider("homoglyph", c.domain)
      elseif pn >= 4 and skel_label == pskel and foreign == 0 then
        consider("lookalike", c.domain)
      elseif pn >= (c.own and 5 or 6) and #label >= 5 then
        local limit = pn >= 9 and 2 or 1
        if M.edit_distance(label, plabel, limit) <= limit or M.edit_distance(skel_label, pskel, limit) <= limit then
          consider("lookalike", c.domain)
        end
      end
      if #tokens > 1 and pn >= 5 then
        for _, tk in ipairs(tokens) do
          if tk == plabel then consider("brand_in_domain", c.domain)
          elseif M.skeleton(tk) == pskel then consider("lookalike", c.domain) end
        end
      end
    end
  end

  if not best and foreign > 0 and latin > 0 then best = { kind = "homoglyph", target = "" } end   -- alphabets mélangés
  return best
end

-- Adresse de l'expéditeur : nom d'affichage protégé (liste de dirigeants {name, address}) usurpé depuis une autre adresse.
function M.vip_spoof(display, address, from_domain, vips, own_domains)
  local own = set_of(own_domains)
  if own[tostring(from_domain or ""):lower()] then return nil end
  local addr = tostring(address or ""):lower()
  for _, vip in ipairs(vips or {}) do
    if M.display_matches(display, vip.name) and addr ~= tostring(vip.address or ""):lower() then
      return vip.name
    end
  end
  return nil
end

return M
