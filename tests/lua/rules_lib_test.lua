-- Tests de rules_lib.lua : exécutés par tests/test_rules.py avec « rspamadm lua -s ».
-- Les cas viennent de tests/data/rules_golden.json (mêmes attentes que le moteur Python).
local lib = dofile(os.getenv("RULES_LIB"))
local ucl = require "ucl"
local failures = {}
local function eq(got, want, what)
  if got ~= want then failures[#failures + 1] = string.format("%s : obtenu %s, attendu %s", what, tostring(got), tostring(want)) end
end

local parser = ucl.parser()
assert(parser:parse_file(os.getenv("RULES_GOLDEN")))
local golden = parser:get_object()
local conf = { signals = golden.signals, thresholds = golden.thresholds }

local function join(t) local out = {} for _, v in ipairs(t) do out[#out + 1] = v end return table.concat(out, ",") end

for _, case in ipairs(golden.cases) do
  local names = {}
  for _, s in ipairs(case.input.symbols) do names[s] = true end
  local lists = { block = lib.compile_list(case.lists.block), safe = lib.compile_list(case.lists.safe) }
  local ctx = lib.build_context({ names = names, raw = case.input.raw, mime_from = case.input.mime_from, env_from = case.input.env_from,
                                  rcpts = case.input.rcpts, ip = case.input.ip }, conf, lists)
  local res = lib.evaluate(case.rules, ctx)
  local exp = case.expected
  for class, want in pairs(exp.scores) do eq(ctx.scores[class], want, case.name .. " : score " .. class) end
  eq(ctx.blocklist, exp.blocklist, case.name .. " : liste de blocage")
  eq(ctx.safelist, exp.safelist, case.name .. " : liste sûre")
  eq(res.final and res.final.id or "nil", exp.final or "nil", case.name .. " : règle finale")
  local ids = {}
  for _, rule in ipairs(res.matched) do ids[#ids + 1] = rule.id end
  eq(join(ids), join(exp.matched), case.name .. " : règles satisfaites")
end

-- interpolation du score de spam
local th = { tag = 5, quarantine = 8, reject = 15 }
eq(lib.spam_score(0, th), 0, "spam 0")
eq(lib.spam_score(-3, th), 0, "spam négatif")
eq(lib.spam_score(4.99, th), 24, "spam 4.99")
eq(lib.spam_score(5, th), 25, "spam 5")
eq(lib.spam_score(7.99, th), 49, "spam 7.99")
eq(lib.spam_score(8, th), 50, "spam 8")
eq(lib.spam_score(14.99, th), 99, "spam 14.99")
eq(lib.spam_score(15, th), 100, "spam 15")
eq(lib.spam_score(80, th), 100, "spam 80")

-- action Rspamd
eq(lib.rspamd_action({ disposition = "deliver" }, true), "no action", "livrer")
eq(lib.rspamd_action({ disposition = "tag" }, true), "add header", "marquer")
eq(lib.rspamd_action({ disposition = "reject" }, true), "reject", "rejeter")
eq(lib.rspamd_action({ disposition = "quarantine" }, true), "quarantine", "quarantaine")
eq(lib.rspamd_action({ disposition = "quarantine" }, false), "add header", "quarantaine désactivée : marquage")
eq(lib.rspamd_action({ disposition = "continue" }, true), nil, "continuer")

-- listes : entrées mal formées ignorées sans erreur
local list = lib.compile_list({ "a@b.fr", "b.fr", "not an ip/99x", "203.0.113.0/24" })
eq(lib.in_list(list, { "x@sub.b.fr" }, ""), true, "sous-domaine")
eq(lib.in_list(list, { "x@autre.fr" }, "203.0.114.1"), false, "hors liste")
eq(lib.in_list(list, {}, "203.0.113.200"), true, "réseau")
eq(lib.in_list(list, {}, "garbage"), false, "IP illisible")

if #failures > 0 then
  print(table.concat(failures, "\n"))
  os.exit(1)
end
print("OK")
