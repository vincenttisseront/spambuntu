-- Spambuntu : sandbox des pièces jointes (premier niveau : analyse statique par le service local).
-- Mode « monitor » : le verdict est journalisé, aucun point n'est ajouté. Mode « enforce » : le verdict devient un symbole que le moteur de règles exploite.
-- Si le service est absent ou lent, rien ne change.
local rspamd_http = require "rspamd_http"
local ucl = require "ucl"

local URL = "http://127.0.0.1:11341/analyze"

local id = rspamd_config:register_symbol({
  name = "SPAMBUNTU_SANDBOX",
  type = "postfilter",
  priority = 8,
  flags = "nostat",
  callback = function(task)
    if not task:has_attachments() then return end
    rspamd_http.request({
      task = task,
      url = URL,
      method = "POST",
      body = task:get_content(),
      timeout = 20.0,
      headers = { ["X-Queue-Id"] = tostring(task:get_queue_id() or "") },
      callback = function(err, code, body)
        if err or code ~= 200 then return end
        local parser = ucl.parser()
        if not parser:parse_string(tostring(body)) then return end
        local res = parser:get_object()
        if type(res) ~= "table" or not res.ok then return end
        local explanation = type(res.explanation) == "string" and res.explanation:gsub("[%[%];,\r\n]", " "):sub(1, 200) or ""
        if res.mode == "monitor" then
          if res.verdict ~= "none" then task:insert_result("SPAMBUNTU_SANDBOX_MONITOR", 0.0, tostring(res.verdict) .. ": " .. explanation) end
          return
        end
        if res.mode ~= "enforce" or type(res.symbols) ~= "table" then return end
        for _, sym in ipairs(res.symbols) do
          if type(sym) == "string" and sym:match("^SPAMBUNTU_SANDBOX_[A-Z_]+$") then
            task:insert_result(sym, 0.0, explanation)
          end
        end
      end,
    })
  end,
})
rspamd_config:set_metric_symbol({ name = "SPAMBUNTU_SANDBOX", score = 0.0, description = "Sandbox des pièces jointes" })

for _, sym in ipairs({ "MALICIOUS", "SUSPICIOUS", "CLEAN", "ERROR", "MONITOR", "URL_MALICIOUS", "URL_SUSPICIOUS" }) do
  rspamd_config:register_symbol({ name = "SPAMBUNTU_SANDBOX_" .. sym, type = "virtual", parent = id, score = 0.0,
                                  description = "Sandbox : " .. sym:lower() })
end
