-- Spambuntu : consulte le service d'analyse IA local pour les messages ambigus (post-filtre).
-- L'IA n'ajoute que des points (et au plus -1), sans pouvoir atteindre le seuil de rejet ; si le service est absent ou lent, rien ne change.
local rspamd_http = require "rspamd_http"
local ucl = require "ucl"

local AID_URL = "http://127.0.0.1:11340/analyze"
local MIN_SCORE = 1.0

local id = rspamd_config:register_symbol({
  name = "SPAMBUNTU_AI",
  type = "postfilter",
  priority = 9,
  flags = "nostat",
  callback = function(task)
    local action = task:get_metric_action()
    local ms = task:get_metric_score()
    local score, reject_at = ms[1], ms[2]
    if action == "reject" or score < MIN_SCORE then return end
    local symbols = {}
    for _, name in ipairs(task:get_symbols()) do symbols[#symbols + 1] = name end
    rspamd_http.request({
      task = task,
      url = AID_URL,
      method = "POST",
      body = task:get_content(),
      timeout = 25.0,
      headers = { ["X-Score"] = tostring(score), ["X-Symbols"] = table.concat(symbols, ",") },
      callback = function(err, code, body)
        if err or code ~= 200 then return end
        local parser = ucl.parser()
        if not parser:parse_string(tostring(body)) then return end
        local res = parser:get_object()
        if type(res) ~= "table" or not res.used then return end
        local points = tonumber(res.points) or 0
        if points < -1 then points = -1 end
        -- L'IA ne peut pas, seule, faire rejeter définitivement un message : au plus la quarantaine.
        local ceiling = (reject_at or 15) - 0.1 - score
        if points > ceiling then points = math.max(ceiling, 0) end
        local explanation = type(res.explanation) == "string" and res.explanation:gsub("[%[%];,\r\n]", " "):sub(1, 200) or ""
        task:insert_result("SPAMBUNTU_AI", points, explanation)
        if type(res.symbols) == "table" then
          for _, sym in ipairs(res.symbols) do
            if type(sym) == "string" and sym:match("^SPAMBUNTU_AI_[A-Z_]+$") then
              task:insert_result(sym, 0.0)
            end
          end
        end
      end,
    })
  end,
})
rspamd_config:set_metric_symbol({ name = "SPAMBUNTU_AI", score = 1.0, description = "Analyse IA (points variables)" })

for _, sym in ipairs({ "IMPERSONATION", "CREDENTIALS", "PAYMENT", "GIFT_CARDS", "INVOICE_CHANGE", "PROMPT_INJECTION",
                       "SPAM", "PHISHING", "BEC", "MALWARE_LURE", "SCAM", "OTHER" }) do
  rspamd_config:register_symbol({ name = "SPAMBUNTU_AI_" .. sym, type = "virtual", parent = id, score = 0.0,
                                  description = "Analyse IA : " .. sym:lower() })
end
