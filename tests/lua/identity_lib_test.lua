-- Tests de identity_lib.lua : exécutés par tests/test_identity.py avec « rspamadm lua -s ».
local lib = dofile(os.getenv("IDENTITY_LIB"))
local failures = {}
local function eq(got, want, what)
  if got ~= want then failures[#failures + 1] = string.format("%s : obtenu %s, attendu %s", what, tostring(got), tostring(want)) end
end

-- normalisation et correspondance du nom d'affichage
eq(lib.normalize_name("Jean-Éric  DUPONT (PDG)"), "jean eric dupont pdg", "normalize")
eq(lib.display_matches("Jean Dupont - PDG", "Jean Dupont"), true, "vip suffixe")
eq(lib.display_matches("DUPONT, Jean", "Jean Dupont"), true, "vip inversé")
eq(lib.display_matches("Jéan Dupont", "Jean Dupont"), true, "vip accent")
eq(lib.display_matches("Jеan Dupont", "Jean Dupont"), true, "vip lettre cyrillique")
eq(lib.display_matches("Jean Martin", "Jean Dupont"), false, "autre personne")
eq(lib.display_matches("Direction générale", "Direction"), false, "nom simple = nom complet")
eq(lib.display_matches("Direction", "Direction"), true, "nom simple identique")
eq(lib.display_matches("", "Jean Dupont"), false, "nom vide")

local vips = { { name = "Jean Dupont", address = "jean.dupont@exemple.fr" } }
eq(lib.vip_spoof("Jean Dupont - PDG", "jean.dupont.ceo@gmail.com", "gmail.com", vips, { "exemple.fr" }), "Jean Dupont", "usurpation vip")
eq(lib.vip_spoof("Jean Dupont", "jean.dupont@exemple.fr", "exemple.fr", vips, { "exemple.fr" }), nil, "vip légitime")
eq(lib.vip_spoof("Jean Dupont", "j.dupont@exemple.fr", "exemple.fr", vips, { "exemple.fr" }), nil, "domaine interne non jugé ici")

-- domaines
local function split(d) return lib.split_domain(d) end
eq((split("mail.exemple.co.uk")), "exemple.co.uk", "split co.uk")
eq((split("impots.gouv.fr")), "impots.gouv.fr", "split gouv.fr")
eq((split("a.b.exemple.fr")), "exemple.fr", "split sous-domaine")

local prot = { own = { "exemple.fr", "ar-systems.fr" }, brands = { "microsoft.com", "paypal.com", "apple.com", "impots.gouv.fr", "google.com" } }
local function kind(d)
  local r = lib.analyze_domain(d, prot)
  return r and r.kind or "none", r and r.target or ""
end
eq((kind("exemple.fr")), "none", "domaine propre")
eq((kind("mail.exemple.fr")), "none", "sous-domaine propre")
eq((kind("microsoft.com")), "none", "marque exacte")
eq((kind("login.microsoft.com")), "none", "sous-domaine de marque")
eq((kind("paypal.fr")), "none", "autre TLD d'une marque : légitime")
eq((kind("exemple.com")), "tld_swap", "autre TLD de votre domaine")
eq((kind("exemple.co")), "tld_swap", "autre TLD (.co)")
eq((kind("micr0soft.com")), "lookalike", "zéro pour o")
eq((kind("rnicrosoft.com")), "lookalike", "rn pour m")
eq((kind("paypa1.com")), "lookalike", "chiffre un pour l")
eq((kind("paypall.com")), "lookalike", "lettre doublée")
eq((kind("paypla.com")), "lookalike", "lettres inversées")
eq((kind("exemple-fr.com")), "brand_in_domain", "votre nom dans un domaine plus long") 
eq((kind("micr0soft-support.test")), "lookalike", "jeton imité dans un domaine composé")
eq((kind("paypal-secure.com")), "brand_in_domain", "marque dans un domaine composé")
eq((kind("ar-system.fr")), "lookalike", "lettre manquante, nom composé")
eq((kind("exampel.fr")), "none", "trop éloigné pour être jugé sans lien")
eq((kind("wikipedia.org")), "none", "domaine sans rapport")
eq((kind("apply.com")), "none", "marque courte : pas de distance d'édition")
eq((kind("goggle.com")), "lookalike", "marque : lettre changée")
eq((kind("impots-gouv.fr")), "brand_in_domain", "marque composée avec suffixe public")

-- Punycode / homoglyphes
eq(lib.decode_domain("xn--pypal-4ve.com"), "pаypal.com", "punycode mixte")
eq(lib.decode_domain("xn--80ak6aa92e.com"), "аррӏе.com", "punycode cyrillique")
eq(lib.decode_domain("exemple.fr"), "exemple.fr", "domaine ASCII inchangé")
eq((kind("xn--80ak6aa92e.com")), "homoglyph", "apple tout en cyrillique")
eq((kind("xn--pypal-4ve.com")), "homoglyph", "paypal avec un a cyrillique")
eq((kind("xn--bcher-kva.example")), "none", "mot allemand légitime (bücher)")
eq(lib.punycode_decode("%%%"), nil, "punycode invalide")

-- distance d'édition et empreinte
eq(lib.edit_distance("kitten", "sitting", 5), 3, "distance")
eq(lib.edit_distance("abcd", "abdc", 2), 1, "transposition")
eq(lib.edit_distance("abcdefgh", "xyz", 2), 3, "limite")
eq(lib.skeleton("Micr0soft"), lib.skeleton("microsoft"), "empreinte")
eq(lib.skeleton("a-b"), "ab", "empreinte sans tiret")

if #failures > 0 then
  for _, f in ipairs(failures) do print("ECHEC " .. f) end
else
  print("TOUT EST BON")
end
