// Adult content keyword patterns for grey-red classification
// Organized by severity — critical = definitive adult, low = could be innocent

export interface KeywordPattern {
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
}

export const ADULT_KEYWORDS: KeywordPattern[] = [
  // ── Critical: unambiguously adult ──
  { pattern: /\bporn(?:hub|star|ography|ographic)?\b/i, severity: 'critical', category: 'explicit' },
  { pattern: /\bhentai\b/i, severity: 'critical', category: 'explicit' },
  { pattern: /\bxxx\b/i, severity: 'critical', category: 'explicit' },
  { pattern: /\bnsfw\b/i, severity: 'critical', category: 'explicit' },
  { pattern: /\bescort\s*(?:service|agency|girl)\b/i, severity: 'critical', category: 'services' },
  { pattern: /\bcam\s*(?:girl|boy|model|show|site)\b/i, severity: 'critical', category: 'cam' },
  { pattern: /\blive\s*(?:cam|sex|nude|strip)\b/i, severity: 'critical', category: 'cam' },
  { pattern: /\bstrip(?:tease|club|chat|per)\b/i, severity: 'critical', category: 'cam' },
  { pattern: /\bonlyfans\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\bfansly\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\bchaturbate\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\bbongacams?\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\bstripchat\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\blivejasmin\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\bmyfreecams?\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\bbrazzers\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\bbangbros\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\brealitykings\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\bxvideos?\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\bxnxx\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\bredtube\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\byouporn\b/i, severity: 'critical', category: 'platform' },
  { pattern: /\bteledildonics?\b/i, severity: 'critical', category: 'tech' },
  { pattern: /\bfleshlight\b/i, severity: 'critical', category: 'product' },
  { pattern: /\bcockring\b/i, severity: 'critical', category: 'product' },
  { pattern: /\bbutt\s*plug\b/i, severity: 'critical', category: 'product' },
  { pattern: /\banal\s*(?:toy|bead|plug|sex)\b/i, severity: 'critical', category: 'product' },

  // ── High: strong adult signal ──
  { pattern: /\bsex\s*(?:toy|shop|doll|game|chat|date|dating|position)\b/i, severity: 'high', category: 'sexual' },
  { pattern: /\bdildo\b/i, severity: 'high', category: 'product' },
  { pattern: /\bvibrator\b/i, severity: 'high', category: 'product' },
  { pattern: /\berotic(?:a|ism)?\b/i, severity: 'high', category: 'sexual' },
  { pattern: /\bfetish\b/i, severity: 'high', category: 'sexual' },
  { pattern: /\bbondage\b/i, severity: 'high', category: 'sexual' },
  { pattern: /\bbdsm\b/i, severity: 'high', category: 'sexual' },
  { pattern: /\borgasm\b/i, severity: 'high', category: 'sexual' },
  { pattern: /\bmasturbat(?:e|ion|ing)\b/i, severity: 'high', category: 'sexual' },
  { pattern: /\bnude(?:s|ity)?\b/i, severity: 'high', category: 'sexual' },
  { pattern: /\bai\s*girlfriend\b/i, severity: 'high', category: 'ai-adult' },
  { pattern: /\bai\s*companion\b/i, severity: 'high', category: 'ai-adult' },
  { pattern: /\bnsfw\s*ai\b/i, severity: 'high', category: 'ai-adult' },
  { pattern: /\bai\s*(?:porn|hentai|nude)\b/i, severity: 'high', category: 'ai-adult' },
  { pattern: /\bdeepfake\b/i, severity: 'high', category: 'ai-adult' },
  { pattern: /\bhookup\s*(?:app|site|dating)\b/i, severity: 'high', category: 'dating' },
  { pattern: /\badult\s*(?:content|site|entertainment|dating|video|film|industry)\b/i, severity: 'high', category: 'general' },
  { pattern: /\bvr\s*porn\b/i, severity: 'high', category: 'tech' },
  { pattern: /\blingerie\b/i, severity: 'high', category: 'product' },
  { pattern: /\blube\b/i, severity: 'high', category: 'product' },
  { pattern: /\bcock\b/i, severity: 'high', category: 'explicit' },

  // ── Medium: contextual, could be innocent ──
  { pattern: /\bsexy\b/i, severity: 'medium', category: 'general' },
  { pattern: /\bintimacy\b/i, severity: 'medium', category: 'general' },
  { pattern: /\bintimate\s*(?:product|toy|wellness|health)\b/i, severity: 'medium', category: 'wellness' },
  { pattern: /\bsexual\s*(?:wellness|health|pleasure)\b/i, severity: 'medium', category: 'wellness' },
  { pattern: /\bpleasure\s*(?:product|toy|device)\b/i, severity: 'medium', category: 'wellness' },
  { pattern: /\bsensual\b/i, severity: 'medium', category: 'general' },
  { pattern: /\bswinger\b/i, severity: 'medium', category: 'dating' },
  { pattern: /\bpolyamor(?:y|ous)\b/i, severity: 'medium', category: 'dating' },
  { pattern: /\bkink(?:y)?\b/i, severity: 'medium', category: 'sexual' },
  { pattern: /\bsexting\b/i, severity: 'medium', category: 'dating' },
  { pattern: /\bsugar\s*(?:daddy|baby|mama)\b/i, severity: 'medium', category: 'dating' },

  // ── Low: weak signal, context-dependent ──
  { pattern: /\bdating\b/i, severity: 'low', category: 'dating' },
  { pattern: /\bmassage\b/i, severity: 'low', category: 'services' },
  { pattern: /\bwellness\b/i, severity: 'low', category: 'wellness' },
  { pattern: /\brelationship\b/i, severity: 'low', category: 'general' },
  { pattern: /\b18\+\b/, severity: 'low', category: 'age-gate' },
  { pattern: /\bage\s*verif(?:y|ication)\b/i, severity: 'low', category: 'age-gate' },
];

export const RTA_LABEL = /\bRTA-5042-1996-1400-1577-RTA\b/;
export const META_RATING_ADULT = /^(adult|mature|RTA-5042)$/i;
