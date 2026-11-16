const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  AlignmentType, HeadingLevel, BorderStyle, WidthType, ShadingType,
  LevelFormat, PageBreak, PageNumber
} = require('docx');
const fs = require('fs');

const C = {
  darkBlue:  "0D1B3E",
  midBlue:   "1E3A8A",
  accent:    "2563EB",
  lightBlue: "DBEAFE",
  borderBlue:"BFDBFE",
  slate:     "475569",
  grayBg:    "F1F5F9",
  white:     "FFFFFF",
  green:     "15803D",
  red:       "DC2626",
  orange:    "EA580C",
};

const b  = { style: BorderStyle.SINGLE, size: 1, color: "CBD5E1" };
const bh = { style: BorderStyle.SINGLE, size: 1, color: C.accent };
const nb = { style: BorderStyle.NONE,   size: 0, color: C.white  };
const borders   = { top: b,  bottom: b,  left: b,  right: b  };
const bordersH  = { top: bh, bottom: bh, left: bh, right: bh };
const noBorders = { top: nb, bottom: nb, left: nb, right: nb };

function sp(before=80, after=80){
  return new Paragraph({ spacing:{before,after}, children:[new TextRun("")] });
}
function pb(){
  return new Paragraph({ children:[new PageBreak()] });
}
function divider(){
  return new Paragraph({
    spacing:{ before:120, after:60 },
    border:{ bottom:{ style:BorderStyle.SINGLE, size:6, color:C.accent, space:1 } },
    children:[new TextRun("")]
  });
}
function sectionBanner(text){
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing:{ before:0, after:200 },
    shading:{ fill:C.darkBlue, type:ShadingType.CLEAR },
    children:[new TextRun({ text, font:"Arial", size:28, bold:true, color:C.white })]
  });
}
function slideLabel(num, title){
  return new Paragraph({
    spacing:{ before:360, after:100 },
    children:[
      new TextRun({ text:`SLIDE ${num}  `, font:"Arial", size:19, bold:true, color:C.accent }),
      new TextRun({ text:`—  ${title}`, font:"Arial", size:19, bold:true, color:C.darkBlue }),
    ]
  });
}
function subLabel(text){
  return new Paragraph({
    spacing:{ before:200, after:80 },
    children:[new TextRun({ text:`▶  ${text}`, font:"Arial", size:20, bold:true, color:C.midBlue })]
  });
}
function body(text, size=22, color=C.darkBlue, before=80, after=80){
  return new Paragraph({
    spacing:{ before, after },
    children:[new TextRun({ text, font:"Arial", size, color })]
  });
}
function bold(text, size=22, color=C.darkBlue, before=80, after=80){
  return new Paragraph({
    spacing:{ before, after },
    children:[new TextRun({ text, font:"Arial", size, color, bold:true })]
  });
}
function highlight(text, before=140, after=140){
  return new Paragraph({
    spacing:{ before, after },
    shading:{ fill:C.lightBlue, type:ShadingType.CLEAR },
    border:{ left:{ style:BorderStyle.SINGLE, size:14, color:C.accent, space:4 } },
    indent:{ left:280, right:200 },
    children:[new TextRun({ text, font:"Arial", size:22, bold:true, color:C.darkBlue })]
  });
}
function tip(text){
  return new Paragraph({
    spacing:{ before:120, after:120 },
    indent:{ left:380 },
    shading:{ fill:C.grayBg, type:ShadingType.CLEAR },
    children:[
      new TextRun({ text:"Conseil :  ", font:"Arial", size:19, bold:true, color:C.slate }),
      new TextRun({ text, font:"Arial", size:19, italics:true, color:C.slate })
    ]
  });
}
function cell(text, bg=C.white, textColor=C.darkBlue, w=4680, isBold=false){
  return new TableCell({
    borders, width:{ size:w, type:WidthType.DXA },
    shading:{ fill:bg, type:ShadingType.CLEAR },
    margins:{ top:80, bottom:80, left:130, right:130 },
    children:[new Paragraph({ children:[new TextRun({ text, font:"Arial", size:18, color:textColor, bold:isBold })] })]
  });
}

const doc = new Document({
  styles:{
    default:{ document:{ run:{ font:"Arial", size:22 } } },
    paragraphStyles:[{
      id:"Heading1", name:"Heading 1", basedOn:"Normal", next:"Normal", quickFormat:true,
      run:{ size:28, bold:true, font:"Arial", color:C.white },
      paragraph:{ spacing:{ before:240, after:200 }, outlineLevel:0 }
    }]
  },
  sections:[{
    properties:{
      page:{
        size:{ width:12240, height:15840 },
        margin:{ top:900, right:1000, bottom:900, left:1000 }
      }
    },
    children:[

// ── PAGE COUVERTURE ──────────────────────────────────────────────────────────
new Paragraph({
  alignment:AlignmentType.CENTER, spacing:{ before:800, after:80 },
  children:[new TextRun({ text:"SCRIPT DE PITCH COMPLET", font:"Arial", size:44, bold:true, color:C.darkBlue })]
}),
new Paragraph({
  alignment:AlignmentType.CENTER, spacing:{ before:0, after:60 },
  children:[new TextRun({ text:"ThreatIntel — Detection automatisee des menaces Email sur un environnement cloud", font:"Arial", size:24, italics:true, color:C.accent })]
}),
new Paragraph({
  alignment:AlignmentType.CENTER, spacing:{ before:0, after:60 },
  children:[new TextRun({ text:"Ferchichi Amira  &  Bouazzi Med Aziz  |  2 TEL 2 - 2 INFO 2  |  ENIT  |  2025-2026", font:"Arial", size:20, color:C.slate })]
}),
new Paragraph({
  alignment:AlignmentType.CENTER, spacing:{ before:0, after:400 },
  children:[new TextRun({ text:"Encadres par : M. Bahloul Faouzi & Mme Regaieg Rym", font:"Arial", size:19, italics:true, color:C.slate })]
}),
divider(), sp(120,60),
new Paragraph({ spacing:{ before:100, after:80 }, children:[new TextRun({ text:"LEGENDE DES SECTIONS", font:"Arial", size:20, bold:true, color:C.midBlue })] }),
new Table({
  width:{ size:9360, type:WidthType.DXA }, columnWidths:[1600,7760],
  rows:[
    new TableRow({ children:[ cell("Parole", C.darkBlue, C.white, 1600, true), cell("Texte a prononcer face au jury.", C.lightBlue, C.darkBlue, 7760) ]}),
    new TableRow({ children:[ cell("Donnees rapport", C.midBlue, C.white, 1600, true), cell("Chiffres et resultats tires de votre rapport technique.", C.white, C.darkBlue, 7760) ]}),
    new TableRow({ children:[ cell("Conseil jury", C.grayBg, C.slate, 1600, true), cell("Technique de presentation, gestion du regard, gestion de la voix.", C.white, C.slate, 7760) ]}),
  ]
}),
sp(200,100),
body("Ce document suit exactement l'ordre de vos slides. Ne lisez jamais ce script devant le jury : interiorisez-le.", 20, C.slate),
pb(),

// ── SLIDES 1-2 ──────────────────────────────────────────────────────────────
sectionBanner("  SLIDES 1 & 2  —  ENTREE EN SCENE & SOMMAIRE"),
slideLabel(1, "PAGE DE TITRE"),
subLabel("Parole — les premieres secondes comptent"),
highlight("Chaque jour, 347 milliards d'emails sont echanges a travers le monde. Et pourtant, 91 % des cyberattaques commencent par un email."),
body("Cette situation a pris une dimension nouvelle avec l'apparition d'outils comme WormGPT et FraudGPT, qui permettent a n'importe quel cybercriminel de generer des emails de phishing parfaitement rediges, invisibles pour les filtres traditionnels."),
body("Les organisations ont deux options : payer des solutions comme Proofpoint — entre 5 000 et 200 000 dollars par an — ou se contenter d'outils gratuits qui ne voient pas les attaques de nouvelle generation."),
highlight("Notre projet s'appelle ThreatIntel. Nous sommes venus combler ce vide."),
tip("Prononcez 'ThreatIntel' distinctement. Ces 30 premieres secondes definissent leur niveau d'attention."),
divider(),
slideLabel(2, "SOMMAIRE"),
subLabel("Parole — annoncez la structure"),
body("Notre presentation suit une logique rigoureuse en 7 etapes : contexte, etat de l'art, evolution des menaces, architecture multi-agents, resultats, comparaison competitive, conclusion."),
highlight("En 7 etapes, vous aurez une vision complete d'un systeme qui protege en temps reel — a un cout proche de zero."),
tip("Regardez votre slide mais gardez le contact visuel avec le jury."),
divider(), pb(),

// ── SLIDE 3 ──────────────────────────────────────────────────────────────────
sectionBanner("  SLIDE 3  —  INTRODUCTION & CONTEXTE"),
slideLabel(3, "LE PROBLEME EN CHIFFRES"),
subLabel("Parole — posez l'urgence"),
body("La messagerie electronique est devenue indispensable. Plus de 347 milliards de messages echanges chaque jour — c'est le canal de communication numero un de toute organisation moderne."),
highlight("En 2024, le FBI a evalue les pertes financieres liees aux attaques BEC a plus de 2,77 milliards de dollars — pour une seule annee."),
body("Les organisations se retrouvent dans une position impossible. D'un cote, des outils integres limites face aux menaces zero-day. De l'autre, des solutions specialisees financierement inaccessibles."),
highlight("C'est precisement ce fosse technologique et financier que ThreatIntel vient combler."),
new Table({
  width:{ size:9360, type:WidthType.DXA }, columnWidths:[5680,3680],
  rows:[
    new TableRow({ children:[ cell("Donnee cle", C.darkBlue, C.white, 5680, true), cell("Source", C.darkBlue, C.white, 3680, true) ]}),
    new TableRow({ children:[ cell("347 milliards d'emails/jour", C.lightBlue, C.darkBlue, 5680), cell("Statista 2024", C.white, C.slate, 3680) ]}),
    new TableRow({ children:[ cell("91 % des cyberattaques commencent par un email", C.lightBlue, C.darkBlue, 5680), cell("Verizon DBIR 2023", C.white, C.slate, 3680) ]}),
    new TableRow({ children:[ cell("2,77 Mds $ de pertes BEC en 2024", C.lightBlue, C.darkBlue, 5680), cell("FBI IC3 Report 2024", C.white, C.slate, 3680) ]}),
    new TableRow({ children:[ cell("Proofpoint : 5 000 a 200 000 $/an", C.lightBlue, C.darkBlue, 5680), cell("Proofpoint pricing", C.white, C.slate, 3680) ]}),
  ]
}),
tip("Si le jury vous demande d'ou viennent vos chiffres, citez-les naturellement — 'selon le rapport IC3 du FBI 2024'."),
divider(), pb(),

// ── SLIDES 4-8 ───────────────────────────────────────────────────────────────
sectionBanner("  SLIDES 4 A 8  —  ETAT DE L'ART & SOLUTIONS EXISTANTES"),
slideLabel(4, "VUE D'ENSEMBLE — 3 APPROCHES"),
body("La securite email a evolue en trois grandes vagues : approche traditionnelle (filtres bayesiens), authentification (SPF/DKIM/DMARC), et analyse de pointe (IA, sandbox, NLP)."),
highlight("Aucune de ces approches ne repond seule au probleme. ThreatIntel les combine toutes trois dans un pipeline unifie."),
divider(),
slideLabel(5, "APPROCHE TRADITIONNELLE & LIMITES"),
body("Les filtres traditionnels — SpamAssassin, Rspamd — reposent sur des mecanismes deterministes : listes noires, regles heuristiques, filtrage bayesien. Efficaces contre le spam massif. Mais contournables de maniere triviale : remplacez 'paypal' par 'paypa1', inserez des espaces invisibles."),
highlight("Les filtres antispam traditionnels constituent une premiere ligne de defense — et seulement ca. Face aux menaces actuelles, ils sont structurellement aveugles."),
divider(),
slideLabel(6, "AUTHENTIFICATION SPF/DKIM/DMARC & LIMITES"),
body("SPF verifie que l'IP expeditrice est autorisee. DKIM ajoute une signature cryptographique. DMARC unifie les deux. Essentiels — mais avec une limite fondamentale : ils valident l'origine, jamais le contenu."),
highlight("L'authentification valide l'origine du message — mais elle reste aveugle face au contenu malveillant envoye depuis des sources legitimes."),
divider(),
slideLabel(7, "ANALYSE DE POINTE — IA & LIMITES"),
body("Sandbox dynamique, NLP, IA comportementale — tres performants contre les menaces sophistiquees. Mais probleme double : cout prohibitif et opacite totale. Proofpoint, Darktrace — des boites noires proprietaires."),
highlight("Tres performantes — mais financierement et techniquement inaccessibles pour la majorite des organisations."),
divider(),
slideLabel(8, "COMPARATIF DES SOLUTIONS AVANCEES"),
body("Voici les solutions analysees dans notre etude comparative."),
new Table({
  width:{ size:9360, type:WidthType.DXA }, columnWidths:[2200,2200,2500,2460],
  rows:[
    new TableRow({ children:[ cell("Solution", C.darkBlue, C.white, 2200, true), cell("Anti-BEC", C.darkBlue, C.white, 2200, true), cell("Sandbox", C.darkBlue, C.white, 2500, true), cell("Cout", C.darkBlue, C.white, 2460, true) ]}),
    new TableRow({ children:[ cell("Microsoft Defender 365", C.grayBg, C.darkBlue, 2200), cell("Partiel", C.grayBg, C.darkBlue, 2200), cell("Oui", C.grayBg, C.green, 2500), cell("Eleve (E5)", C.grayBg, C.orange, 2460) ]}),
    new TableRow({ children:[ cell("Proofpoint", C.white, C.darkBlue, 2200), cell("Oui", C.white, C.green, 2200), cell("Oui (avance)", C.white, C.green, 2500), cell("Tres eleve", C.white, C.red, 2460) ]}),
    new TableRow({ children:[ cell("Abnormal Security", C.grayBg, C.darkBlue, 2200), cell("Oui (avance)", C.grayBg, C.green, 2200), cell("Non (API only)", C.grayBg, C.red, 2500), cell("Tres eleve", C.grayBg, C.red, 2460) ]}),
    new TableRow({ children:[ cell("Darktrace Antigena", C.white, C.darkBlue, 2200), cell("Oui (avance)", C.white, C.green, 2200), cell("Oui", C.white, C.green, 2500), cell("Tres eleve", C.white, C.red, 2460) ]}),
    new TableRow({ children:[ cell("SpamAssassin", C.grayBg, C.darkBlue, 2200), cell("Non (invisible)", C.grayBg, C.red, 2200), cell("Non", C.grayBg, C.red, 2500), cell("Gratuit", C.grayBg, C.green, 2460) ]}),
    new TableRow({ children:[ cell("ThreatIntel (notre solution)", C.lightBlue, C.darkBlue, 2200, true), cell("Oui (NLP+BEC)", C.lightBlue, C.green, 2200, true), cell("Oui (Azure ACI)", C.lightBlue, C.green, 2500, true), cell("Open-source", C.lightBlue, C.green, 2460, true) ]}),
  ]
}),
tip("Ce tableau est issu du Tableau 2.2 de votre rapport (p.27). Le jury peut l'avoir sous les yeux."),
divider(), pb(),

// ── SLIDES 9-12 ──────────────────────────────────────────────────────────────
sectionBanner("  SLIDES 9 A 12  —  EVOLUTION DES MENACES (3 GENERATIONS)"),
slideLabel(9, "INTRODUCTION — LES ATTAQUANTS N'ONT JAMAIS CESSE D'EVOLUER"),
highlight("Trois generations. Trois ruptures technologiques. Trois reponses insuffisantes. Et une quatrieme ere qui commence — celle ou l'IA generative arme les attaquants."),
divider(),
slideLabel(10, "GENERATION 1 — LE SPAM DE MASSE"),
body("Campagnes indiscriminées a grande echelle. Reponse : filtres bayesiens. Efficaces sur le volume. Mais contournables en quelques secondes : substitution de caracteres, espaces invisibles, texte remplace par une image."),
highlight("Le filtre bayesien est aveugle des qu'on change un seul caractere dans un mot-cle. C'est une limite structurelle, pas un bug."),
divider(),
slideLabel(11, "GENERATION 2 — LE SPEAR PHISHING CIBLE"),
body("Cible une personne precise en usurpant une identite connue. Reponse : SPF, DKIM, DMARC. Essentiels — mais si un compte legitime est compromis, il passe tous les controles. Le contenu du message n'est jamais verifie."),
highlight("L'authentification valide qui envoie. Jamais ce qui est envoye."),
divider(),
slideLabel(12, "GENERATION 3 — L'IA GENERATIVE AU SERVICE DES ATTAQUANTS"),
subLabel("Parole — ralentissez ici"),
body("WormGPT et FraudGPT permettent a des cybercriminels — meme peu experimentes — de generer automatiquement des emails BEC parfaitement rediges, contextualises, sans URL suspecte, sans piece jointe. Ces emails imitent le style d'un dirigeant. Ils creent une urgence artificielle. Ils demandent un virement. Ils sont indetectables par tous les filtres traditionnels."),
highlight("C'est precisement cette troisieme generation que ThreatIntel adresse — la ou toutes les solutions existantes echouent."),
tip("Marquez une vraie pause apres 'ils fonctionnent'. Laissez le jury ressentir la menace."),
divider(), pb(),

// ── SLIDES 13-15 ─────────────────────────────────────────────────────────────
sectionBanner("  SLIDES 13 A 15  —  PROBLEMATIQUE & LES 3 LACUNES"),
slideLabel(13, "LES LIMITES DE L'EXISTANT"),
subLabel("Parole — comptez sur vos doigts"),
body("Premiere lacune : le fosse financier. Les solutions avancees sont inaccessibles a la majorite. Les organisations les plus vulnerables — PME, institutions academiques — sont celles qui ne peuvent pas se les offrir."),
body("Deuxieme lacune : l'angle mort semantique. La majorite des solutions ignorent le contenu textuel. Or les attaques BEC modernes ne contiennent ni URL ni piece jointe."),
body("Troisieme lacune : l'absence d'automatisation de la reponse. Meme quand une solution detecte une menace, l'action reste manuelle."),
highlight("Ces trois lacunes definissent exactement ce que ThreatIntel resout — simultanement."),
divider(),
slideLabel(15, "LA QUESTION DE RECHERCHE"),
highlight("Comment construire un systeme multi-agents capable d'analyser automatiquement chaque email recu selon plusieurs axes de securite complementaires, et d'alerter l'analyste en temps reel ?"),
body("Cette question n'est pas rhetorique. Elle a une reponse. Et vous allez la voir fonctionner."),
tip("Regardez le jury dans les yeux en prononcant la derniere phrase. Le 'vous allez la voir fonctionner' doit sonner comme une promesse tenue."),
divider(), pb(),

// ── SLIDES 16-19 ─────────────────────────────────────────────────────────────
sectionBanner("  SLIDES 16 A 19  —  ARCHITECTURE, INFRASTRUCTURE, PIPELINE"),
slideLabel(16, "VUE D'ENSEMBLE DE L'ARCHITECTURE"),
body("ThreatIntel repose sur cinq agents specialises, orchestres en parallele sur un cloud hybride Azure et Google Cloud Platform. Ce parallelisme nous permet d'atteindre une latence mediane de 1,8 seconde en configuration Production Small."),
highlight("1,8 seconde. C'est le temps entre la reception d'un email et le verdict de securite — agents NLP, URL, Auth et Sandbox inclus."),
new Table({
  width:{ size:9360, type:WidthType.DXA }, columnWidths:[3200,3200,2960],
  rows:[
    new TableRow({ children:[ cell("Service Azure", C.darkBlue, C.white, 3200, true), cell("Role", C.darkBlue, C.white, 3200, true), cell("Config", C.darkBlue, C.white, 2960, true) ]}),
    new TableRow({ children:[ cell("Azure Functions", C.grayBg, C.darkBlue, 3200), cell("Orchestrateur Python asyncio", C.grayBg, C.darkBlue, 3200), cell("Mode Consumption", C.grayBg, C.slate, 2960) ]}),
    new TableRow({ children:[ cell("Azure Container Instances", C.white, C.darkBlue, 3200), cell("Sandbox VM ephemere", C.white, C.darkBlue, 3200), cell("python:3.11-slim / Zero Persistence", C.white, C.slate, 2960) ]}),
    new TableRow({ children:[ cell("Azure Cosmos DB", C.grayBg, C.darkBlue, 3200), cell("Persistance des rapports SOC", C.grayBg, C.darkBlue, 3200), cell("400 RU/s (prod small)", C.grayBg, C.slate, 2960) ]}),
    new TableRow({ children:[ cell("Azure Cache for Redis", C.white, C.darkBlue, 3200), cell("Cache verdicts + URLs (TTL 1h)", C.white, C.darkBlue, 3200), cell("Cluster 6 Go", C.white, C.slate, 2960) ]}),
    new TableRow({ children:[ cell("GCP — Gmail API", C.lightBlue, C.darkBlue, 3200), cell("Reception emails via OAuth 2.0", C.lightBlue, C.darkBlue, 3200), cell("Permissions lecture seule", C.lightBlue, C.slate, 2960) ]}),
  ]
}),
tip("Ce tableau est issu du Tableau 4.1 de votre rapport (p.47)."),
divider(),
slideLabel(18, "AGENT SANDBOX EN DETAIL"),
body("Quand un email contient une piece jointe, l'orchestrateur la valide puis la uploade dans Azure Blob Storage. Une Azure Container Instance s'allume avec image python:3.11-slim et restrictions reseau strictes."),
body("PDF : extraction des liens embarques, detection de JavaScript. DOCX/XLSX : detection de macros VBA et commandes PowerShell. ZIP : extraction recursive."),
highlight("La VM est detruite immediatement apres l'analyse — Zero Persistence. Aucune trace n'est conservee dans l'environnement de production."),
tip("Si le jury demande comment vous garantissez l'isolation — repondez : cgroups, seccomp, reseau sandboxe, Zero Persistence."),
divider(), pb(),

// ── SLIDES 20-25 ─────────────────────────────────────────────────────────────
sectionBanner("  SLIDES 20 A 25  —  LES AGENTS & LE MOTEUR DE FUSION"),
slideLabel(21, "SCORE AUTH — LEGITIMITE TECHNIQUE DE L'EXPEDITEUR"),
body("Le score d'authentification part de zero et monte par accumulation de malus. SPF, DKIM et DMARC tous valides : score de base a 5/100. SPF absent : +20. DKIM absent : +40. Homographe Unicode detecte : hard rule, score critique immediat."),
highlight("Un 'a' cyrillique dans 'paypal.com' passe inapercу a l'oeil humain. Notre agent le detecte en millisecondes via une analyse Unicode character-by-character."),
divider(),
slideLabel(22, "SCORE URL — REPUTATION DE CHAQUE LIEN"),
body("Logique MAX — le score final est celui de l'URL la plus dangereuse. Sources : VirusTotal (70+ moteurs), PhishTank, Google Safe Browsing, WHOIS pour l'age du domaine."),
highlight("Domaine cree il y a moins de 48h : +50 pts. IP brute au lieu d'un nom : +75 pts. URL en liste noire : score 100, bloque immediatement."),
tip("Si le jury demande ce qui se passe quand VirusTotal est indisponible : circuit breaker OPEN apres 3 timeouts, bascule sur liste noire locale."),
divider(),
slideLabel(23, "SCORE NLP+BEC — L'ANALYSE SEMANTIQUE"),
subLabel("Parole — votre argument le plus differenciateur"),
body("Trois modeles en fusion ponderee :"),
body("DistilBERT a 45 % : 40 % plus leger, 60 % plus rapide que BERT, 97 % des performances. Detecte les structures classiques de phishing."),
body("RoBERTa a 30 % : reentrainee sur 160 Go de texte. Analyse le ton : urgence, menace, autorite. Ideale pour les BEC sans URL ni piece jointe."),
body("Fuzzy matching a 25 % : typosquatting, mots-cles BEC — 'RIB', 'Urgent', 'Virement', 'Confidentiel'."),
new Paragraph({
  spacing:{ before:100, after:100 },
  shading:{ fill:C.darkBlue, type:ShadingType.CLEAR },
  indent:{ left:200, right:200 },
  children:[new TextRun({ text:"score_nlp = 0,45 x DistilBERT + 0,30 x RoBERTa + 0,25 x Fuzzy", font:"Courier New", size:20, color:C.white, bold:true })]
}),
highlight("Si un email contient un ton imperatif combine a une demande de virement — le score NLP grimpe drastiquement, independamment des autres agents."),
divider(),
slideLabel(25, "MOTEUR DE FUSION & VERDICT FINAL"),
body("Etape 1 — Hard Rules : si un seul score depasse un seuil critique, email bloque immediatement sans vote."),
body("Etape 2 — Random Forest : analyse la combinaison des quatre scores via un modele appris sur corpus d'emails etiquetes."),
new Paragraph({
  spacing:{ before:100, after:100 },
  shading:{ fill:C.darkBlue, type:ShadingType.CLEAR },
  indent:{ left:200, right:200 },
  children:[new TextRun({ text:"S_final = w1*S_Auth + w2*S_URL + w3*S_NLP + w4*S_Sandbox", font:"Courier New", size:20, color:C.white, bold:true })]
}),
highlight("Verdict : Sain (0-25) delivre. Suspect (26-55) quarantaine + alerte. Danger (56-85) bloque. Critique (86-100) bloque + rapport d'incident automatique."),
tip("La synergie Random Forest est votre argument technique le plus fort : deux scores moderes peuvent ensemble donner un verdict Danger."),
divider(), pb(),

// ── SLIDES 26-28 ─────────────────────────────────────────────────────────────
sectionBanner("  SLIDES 26 A 28  —  RESULTATS EXPERIMENTAUX & COMPARAISON"),
slideLabel(27, "LE DASHBOARD — RESULTATS EN PRODUCTION"),
body("Sur les 103 emails analyses en conditions reelles :"),
new Table({
  width:{ size:9360, type:WidthType.DXA }, columnWidths:[2340,2340,2340,2340],
  rows:[
    new TableRow({ children:[ cell("Total analyses", C.darkBlue, C.white, 2340, true), cell("DANGER", C.red, C.white, 2340, true), cell("SUSPECT", C.orange, C.white, 2340, true), cell("SAIN", C.green, C.white, 2340, true) ]}),
    new TableRow({ children:[ cell("103", C.lightBlue, C.darkBlue, 2340, true), cell("14", C.white, C.red, 2340, true), cell("5", C.white, C.orange, 2340, true), cell("84", C.white, C.green, 2340, true) ]}),
  ]
}),
sp(60,40),
new Table({
  width:{ size:9360, type:WidthType.DXA }, columnWidths:[2800,1760,1760,3040],
  rows:[
    new TableRow({ children:[ cell("Scenario", C.darkBlue, C.white, 2800, true), cell("Latence", C.darkBlue, C.white, 1760, true), cell("Confiance", C.darkBlue, C.white, 1760, true), cell("Resultat", C.darkBlue, C.white, 3040, true) ]}),
    new TableRow({ children:[ cell("Phishing simple (sans PJ)", C.grayBg, C.darkBlue, 2800), cell("2,1 s", C.grayBg, C.darkBlue, 1760), cell("0,93", C.grayBg, C.green, 1760), cell("Verdict Danger — pipeline complet", C.grayBg, C.darkBlue, 3040) ]}),
    new TableRow({ children:[ cell("PJ malveillante (sandbox)", C.white, C.darkBlue, 2800), cell("5,2 s", C.white, C.darkBlue, 1760), cell("0,98", C.white, C.green, 1760), cell("Verdict Quarantine — sandbox +2,5s", C.white, C.darkBlue, 3040) ]}),
    new TableRow({ children:[ cell("Panne API externe (fallback)", C.grayBg, C.darkBlue, 2800), cell("1,8 s", C.grayBg, C.darkBlue, 1760), cell("0,72", C.grayBg, C.orange, 1760), cell("Analyse partielle — continuite assuree", C.grayBg, C.darkBlue, 3040) ]}),
    new TableRow({ children:[ cell("Cache Redis (cache hit)", C.white, C.darkBlue, 2800), cell("0,015 s", C.white, C.green, 1760), cell("—", C.white, C.darkBlue, 1760), cell("Reduction latence de 99,35 %", C.white, C.green, 3040) ]}),
  ]
}),
highlight("Ces resultats sont issus d'une vraie boite mail, en temps reel. Ce n'est pas une simulation — c'est de la production."),
tip("Ces chiffres sont issus du Tableau 4.5 de votre rapport (p.55). Connaissez-les par coeur."),
divider(),
slideLabel(28, "COMPARAISON COMPETITIVE"),
body("ThreatIntel face a la concurrence sur les criteres qui comptent :"),
body("Cout : open-source, contre des dizaines ou centaines de milliers de dollars. Transparence : totale — chaque agent explique sa decision. Proofpoint et Darktrace fonctionnent en boite noire. Personnalisable : oui. Architecture multi-agents : oui. Deployable on-premise : oui."),
highlight("Performances equivalentes. Cout radicalement inferieur. Fonctionnement entierement transparent. C'est le positionnement de ThreatIntel."),
tip("Insistez sur 'open-source' et 'transparent' — ce sont vos arguments differenciateurs absolus."),
divider(), pb(),

// ── SLIDES 29-31 ─────────────────────────────────────────────────────────────
sectionBanner("  SLIDES 29 A 31  —  CONCLUSION, PERSPECTIVES & QUESTIONS"),
slideLabel(29, "CONCLUSION"),
subLabel("Parole — la synthese finale, debout, sans notes"),
body("Nous avons commence avec une question simple :"),
highlight("Peut-on rendre accessible une protection email de niveau SOC a des organisations qui n'ont pas les moyens de Proofpoint ou Darktrace ?"),
body("La reponse est oui. Et elle s'appelle ThreatIntel. Un systeme multi-agents. Open-source. Deployable en cloud hybride Azure et GCP. Capable de detecter les menaces de troisieme generation en moins de deux secondes. A cout quasi nul. Avec une transparence totale sur chaque decision."),
highlight("C'est notre contribution. Elle est concrete, mesurable, et deployee en production."),
tip("Prononcez la conclusion debout, pose. Pas de notes. Regardez le jury. Ces dernieres secondes sont celles qu'ils retiennent."),
divider(),
slideLabel(30, "PERSPECTIVES & ROADMAP"),
body("Court terme : etendre la connexion au-dela de Gmail — Outlook, Microsoft 365, ProtonMail, Teams, Slack."),
body("Moyen terme : interface SOC dediee avec visualisation des verdicts et validation humaine des cas ambigus."),
body("Long terme : modeles multilingues, detection sur d'autres canaux, et learning loop — le systeme apprend de chaque verdict SOC pour affiner ses modeles dynamiquement."),
highlight("Nous avons construit les fondations. La prochaine version apprend d'elle-meme."),
divider(),
slideLabel(31, "MERCI — SEANCE DE QUESTIONS"),
body("Merci pour votre attention. Nous sommes a votre disposition pour toutes vos questions."),
highlight("ThreatIntel a ete concu pour etre comprehensible, transparent et defendable — a chaque niveau de detail."),
sp(80,60),

subLabel("QUESTIONS PROBABLES DU JURY — PREPAREZ VOS REPONSES"),
new Table({
  width:{ size:9360, type:WidthType.DXA }, columnWidths:[3400,5960],
  rows:[
    new TableRow({ children:[ cell("Question probable", C.darkBlue, C.white, 3400, true), cell("Reponse preparee", C.darkBlue, C.white, 5960, true) ]}),
    new TableRow({ children:[ cell("Pourquoi Random Forest et pas un LLM ?", C.grayBg, C.darkBlue, 3400), cell("Interpretabilite, legerete, rapidite. Un RF donne des probabilites lisibles par un analyste SOC. Un LLM en scoring final serait une boite noire — exactement ce qu'on critique chez Darktrace.", C.grayBg, C.darkBlue, 5960) ]}),
    new TableRow({ children:[ cell("Quelle est la latence reelle ?", C.white, C.darkBlue, 3400), cell("1,8 s mediane (p50) en Production Small. Sans sandbox : < 500 ms. Avec sandbox sur PJ : 5,2 s. Cache hit : 15 ms [Tableau 4.4-4.5, p.54-55].", C.white, C.darkBlue, 5960) ]}),
    new TableRow({ children:[ cell("Comment gerez-vous les faux positifs ?", C.grayBg, C.darkBlue, 3400), cell("Seuils calibres par categorie (Suspect vs Danger). Score neutre 0,5 si sandbox echoue. Marquage partial:true si fallback actif. Validation humaine SOC disponible.", C.grayBg, C.darkBlue, 5960) ]}),
    new TableRow({ children:[ cell("La VM sandbox peut-elle etre compromise ?", C.white, C.darkBlue, 3400), cell("Non. Zero Persistence : VM detruite apres chaque analyse. Reseau sandboxe. Image python:3.11-slim. Isolation par cgroups et seccomp.", C.white, C.darkBlue, 5960) ]}),
    new TableRow({ children:[ cell("Pourquoi Azure et pas AWS ?", C.grayBg, C.darkBlue, 3400), cell("Azure Container Instances offre le meilleur rapport isolement/cout/latence pour les sandboxes ephemeres. Future integration Microsoft 365 / Exchange Online naturelle.", C.grayBg, C.darkBlue, 5960) ]}),
    new TableRow({ children:[ cell("Pourquoi DistilBERT et pas BERT ?", C.white, C.darkBlue, 3400), cell("DistilBERT est 40 % plus leger et 60 % plus rapide, avec 97 % des performances de BERT. Sa legerete est critique pour un deploiement Cloud a faible latence.", C.white, C.darkBlue, 5960) ]}),
    new TableRow({ children:[ cell("Que se passe-t-il si VirusTotal est indisponible ?", C.grayBg, C.darkBlue, 3400), cell("Circuit breaker OPEN apres 3 timeouts. L'agent URL bascule sur liste noire locale. Confiance reduite a 0,72 vs 0,91 normal. Analyse marquee partial:true.", C.grayBg, C.darkBlue, 5960) ]}),
    new TableRow({ children:[ cell("Comment fonctionne le cache Redis ?", C.white, C.darkBlue, 3400), cell("TTL de 3600 secondes. Cache miss : 2300 ms. Cache hit : 15 ms. Reduction de latence de 99,35 %. Tres utile pour les campagnes qui envoient le meme email a de nombreux destinataires.", C.white, C.darkBlue, 5960) ]}),
    new TableRow({ children:[ cell("Avez-vous teste avec des emails reels ?", C.grayBg, C.darkBlue, 3400), cell("Oui. 103 emails analyses en conditions reelles sur une vraie boite Gmail : 14 DANGER, 5 SUSPECT, 84 SAIN. Les 4 scenarios de test sont documentes dans le Tableau 4.5 p.55.", C.grayBg, C.darkBlue, 5960) ]}),
    new TableRow({ children:[ cell("Quelle est la disponibilite cible ?", C.white, C.darkBlue, 3400), cell("99,5 % pour l'integralite du pipeline. Garanti par : Service Bus (decouplage), circuit breaker + retry backoff exponentiel, graceful fallback par agent.", C.white, C.darkBlue, 5960) ]}),
  ]
}),
sp(200,100),
new Paragraph({
  alignment:AlignmentType.CENTER,
  spacing:{ before:400, after:200 },
  shading:{ fill:C.darkBlue, type:ShadingType.CLEAR },
  children:[new TextRun({ text:"Bonne chance pour votre soutenance !", font:"Arial", size:32, bold:true, color:C.white })]
}),

    ] // children
  }]  // sections
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync('SCRIPT_PITCH_ThreatIntel.docx', buffer);
  console.log('Document genere : SCRIPT_PITCH_ThreatIntel.docx');
}).catch(err => {
  console.error('Erreur:', err);
});
