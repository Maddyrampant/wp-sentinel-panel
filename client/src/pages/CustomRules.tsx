import { useEffect, useState, useMemo } from 'react';
import { getCustomRules, saveCustomRule, deleteCustomRule, importRules, exportRules } from '../api/client';
import type { CustomRule } from '../types';
import { useTranslation } from '../i18n';
import { IconDoor, IconEyeOff, IconSpider, IconServer, IconRefresh, IconArrowUpRight, IconKey, IconZap, IconSecurity, IconLock, IconGlobe, IconCode, IconFileSearch, IconBug, IconImport, IconExport, IconCategory } from '../components/Icons';

const sevColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const confColors: Record<string, string> = {
  high: 'bg-green-500/20 text-green-400 border-green-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const categoryIcons: Record<string, React.ReactNode> = {
  backdoor: <IconDoor size={16} />, obfuscation: <IconEyeOff size={16} />, webshell: <IconSpider size={16} />, wordpress: <IconServer size={16} />,
  persistence: <IconRefresh size={16} />, redirect: <IconArrowUpRight size={16} />, secrets: <IconKey size={16} />, injection: <IconZap size={16} />,
  integrity: <IconSecurity size={16} />, security: <IconLock size={16} />, 'external-access': <IconGlobe size={16} />,
  'code-pattern': <IconCode size={16} />, 'file-analysis': <IconFileSearch size={16} />, malware: <IconBug size={16} />,
};

const emptyRule: Partial<CustomRule> = {
  name: '', description: '', pattern: '', patterns: [], pathPatterns: [], targetFiles: [],
  isRegex: true, severity: 'medium', category: 'security', confidence: 'medium',
  recommendation: '', tags: [], filePattern: '*', enabled: true,
};

export default function CustomRules() {
  const { t } = useTranslation();
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Partial<CustomRule>>(emptyRule);
  const [testInput, setTestInput] = useState('');
  const [testResult, setTestResult] = useState<'match' | 'no-match' | null>(null);
  const [catFilter, setCatFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [newPattern, setNewPattern] = useState('');
  const [newPathPattern, setNewPathPattern] = useState('');
  const [newTargetFile, setNewTargetFile] = useState('');
  const [newTag, setNewTag] = useState('');
  const [importing, setImporting] = useState(false);

  const load = () => getCustomRules().then(d => setRules(Array.isArray(d) ? d : [])).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  const categories = useMemo(() => {
    const cats = new Map<string, number>();
    for (const r of rules) { cats.set(r.category, (cats.get(r.category) || 0) + 1); }
    return Array.from(cats.entries()).sort((a, b) => b[1] - a[1]);
  }, [rules]);

  const filteredRules = useMemo(() => {
    let result = Array.isArray(rules) ? rules : [];
    if (catFilter !== 'all') result = result.filter(r => r.category === catFilter);
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(r => r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.description.toLowerCase().includes(q) || r.tags.some(tag => tag.toLowerCase().includes(q)));
    }
    return result;
  }, [rules, catFilter, search]);

  const handleSave = async () => {
    if (!editing.name) return;
    const patterns = editing.patterns && editing.patterns.length > 0 ? editing.patterns : (editing.pattern ? [editing.pattern] : []);
    await saveCustomRule({ ...editing, patterns });
    setShowForm(false);
    setEditing(emptyRule);
    load();
  };

  const handleDelete = async (id: string) => {
    if (!confirm(t.customRules.deleteConfirm)) return;
    await deleteCustomRule(id);
    load();
  };

  const handleToggle = async (rule: CustomRule) => {
    await saveCustomRule({ ...rule, enabled: !rule.enabled });
    load();
  };

  const handleTest = () => {
    if (!editing.pattern || !testInput) { setTestResult(null); return; }
    try {
      if (editing.isRegex) {
        const regex = new RegExp(editing.pattern, 'gm');
        setTestResult(regex.test(testInput) ? 'match' : 'no-match');
      } else {
        setTestResult(testInput.includes(editing.pattern) ? 'match' : 'no-match');
      }
    } catch { setTestResult(null); }
  };

  const handleEdit = (rule: CustomRule) => {
    setEditing({ ...rule });
    setShowForm(true);
    setTestResult(null);
    setTestInput('');
  };

  const handleImport = async () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.yaml,.yml';
    input.onchange = async (e: any) => {
      const file = e.target.files[0];
      if (!file) return;
      setImporting(true);
      try {
        const content = await file.text();
        const result = await importRules(content);
        alert(`Imported ${result.imported} rules`);
        load();
      } catch (err: any) {
        alert(`Import failed: ${err.message}`);
      }
      setImporting(false);
    };
    input.click();
  };

  const handleExport = async () => {
    try {
      const yaml = await exportRules();
      const blob = new Blob([yaml], { type: 'text/yaml' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'wp-sentinel-rules.yaml';
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Export failed: ${err.message}`);
    }
  };

  const addPattern = () => {
    if (!newPattern.trim()) return;
    const patterns = [...(editing.patterns || []), newPattern.trim()];
    setEditing({ ...editing, patterns, pattern: patterns[0] || '' });
    setNewPattern('');
  };

  const removePattern = (idx: number) => {
    const patterns = (editing.patterns || []).filter((_, i) => i !== idx);
    setEditing({ ...editing, patterns, pattern: patterns[0] || '' });
  };

  const addPathPattern = () => {
    if (!newPathPattern.trim()) return;
    setEditing({ ...editing, pathPatterns: [...(editing.pathPatterns || []), newPathPattern.trim()] });
    setNewPathPattern('');
  };

  const removePathPattern = (idx: number) => {
    setEditing({ ...editing, pathPatterns: (editing.pathPatterns || []).filter((_, i) => i !== idx) });
  };

  const addTargetFile = () => {
    if (!newTargetFile.trim()) return;
    setEditing({ ...editing, targetFiles: [...(editing.targetFiles || []), newTargetFile.trim()] });
    setNewTargetFile('');
  };

  const removeTargetFile = (idx: number) => {
    setEditing({ ...editing, targetFiles: (editing.targetFiles || []).filter((_, i) => i !== idx) });
  };

  const addTag = () => {
    if (!newTag.trim()) return;
    setEditing({ ...editing, tags: [...(editing.tags || []), newTag.trim()] });
    setNewTag('');
  };

  const removeTag = (idx: number) => {
    setEditing({ ...editing, tags: (editing.tags || []).filter((_, i) => i !== idx) });
  };

  if (loading) return <div className="text-center py-20 text-dark-500">{t.dashboard.loading}</div>;

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white">{t.customRules.title}</h1>
          <p className="text-dark-500 mt-1">{rules.length} {t.customRules.rulesTotal || 'rules'} | {rules.filter(r => r.isBuiltin).length} built-in | {rules.filter(r => !r.isBuiltin).length} custom</p>
        </div>
        <div className="flex gap-2">
          <button onClick={handleImport} disabled={importing}
            className="bg-dark-700 hover:bg-dark-600 text-white px-4 py-2 rounded-lg text-sm transition-colors disabled:opacity-50 flex items-center gap-1.5">
            <IconImport size={14} /> {t.customRules.importYaml || 'Import YAML'}
          </button>
          <button onClick={handleExport}
            className="bg-dark-700 hover:bg-dark-600 text-white px-4 py-2 rounded-lg text-sm transition-colors flex items-center gap-1.5">
            <IconExport size={14} /> {t.customRules.exportYaml || 'Export YAML'}
          </button>
          <button onClick={() => { setEditing(emptyRule); setShowForm(true); setTestResult(null); }}
            className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
            + {t.customRules.addRule}
          </button>
        </div>
      </div>

      {/* Enhanced Form */}
      {showForm && (
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6 mb-6">
          <h3 className="text-lg font-semibold text-white mb-4">{editing.id ? t.customRules.editRule : t.customRules.addRule}</h3>

          {/* Name + Description */}
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-xs text-dark-500 mb-1">{t.customRules.ruleName}</label>
              <input value={editing.name || ''} onChange={e => setEditing({ ...editing, name: e.target.value })}
                className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2 text-white text-sm focus:outline-none focus:border-blue-500"
                placeholder={t.customRules.ruleNamePlaceholder} />
            </div>
            <div>
              <label className="block text-xs text-dark-500 mb-1">{t.customRules.description}</label>
              <input value={editing.description || ''} onChange={e => setEditing({ ...editing, description: e.target.value })}
                className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2 text-white text-sm focus:outline-none focus:border-blue-500"
                placeholder={t.customRules.descriptionPlaceholder} />
            </div>
          </div>

          {/* Patterns (multi) */}
          <div className="mb-4">
            <label className="block text-xs text-dark-500 mb-1">{t.customRules.patterns || 'Patterns'}</label>
            <div className="flex gap-2 mb-2">
              <input value={newPattern} onChange={e => setNewPattern(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addPattern()}
                className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-4 py-2 text-white text-sm font-mono focus:outline-none focus:border-blue-500"
                placeholder={t.customRules.patternPlaceholder} />
              <button onClick={addPattern} className="bg-dark-700 hover:bg-dark-600 text-white px-3 py-2 rounded-lg text-sm">+</button>
            </div>
            <div className="flex flex-wrap gap-1">
              {(editing.patterns || []).map((p, i) => (
                <span key={i} className="bg-blue-500/10 text-blue-400 px-2 py-1 rounded text-xs font-mono flex items-center gap-1">
                  {p.substring(0, 60)}{p.length > 60 ? '...' : ''}
                  <button onClick={() => removePattern(i)} className="text-blue-300 hover:text-red-400 ml-1">×</button>
                </span>
              ))}
            </div>
          </div>

          {/* Path Patterns */}
          <div className="mb-4">
            <label className="block text-xs text-dark-500 mb-1">{t.customRules.pathPatterns || 'Path Patterns (regex for file paths)'}</label>
            <div className="flex gap-2 mb-2">
              <input value={newPathPattern} onChange={e => setNewPathPattern(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addPathPattern()}
                className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-4 py-2 text-white text-sm font-mono focus:outline-none focus:border-blue-500"
                placeholder="e.g. wp-content/uploads/ or /\\.php$/" />
              <button onClick={addPathPattern} className="bg-dark-700 hover:bg-dark-600 text-white px-3 py-2 rounded-lg text-sm">+</button>
            </div>
            <div className="flex flex-wrap gap-1">
              {(editing.pathPatterns || []).map((p, i) => (
                <span key={i} className="bg-purple-500/10 text-purple-400 px-2 py-1 rounded text-xs font-mono flex items-center gap-1">
                  {p}
                  <button onClick={() => removePathPattern(i)} className="text-purple-300 hover:text-red-400 ml-1">×</button>
                </span>
              ))}
            </div>
          </div>

          {/* Target Files */}
          <div className="mb-4">
            <label className="block text-xs text-dark-500 mb-1">{t.customRules.targetFiles || 'Target Files'}</label>
            <div className="flex gap-2 mb-2">
              <input value={newTargetFile} onChange={e => setNewTargetFile(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addTargetFile()}
                className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-4 py-2 text-white text-sm font-mono focus:outline-none focus:border-blue-500"
                placeholder="e.g. wp-config.php, .htaccess" />
              <button onClick={addTargetFile} className="bg-dark-700 hover:bg-dark-600 text-white px-3 py-2 rounded-lg text-sm">+</button>
            </div>
            <div className="flex flex-wrap gap-1">
              {(editing.targetFiles || []).map((f, i) => (
                <span key={i} className="bg-orange-500/10 text-orange-400 px-2 py-1 rounded text-xs font-mono flex items-center gap-1">
                  {f}
                  <button onClick={() => removeTargetFile(i)} className="text-orange-300 hover:text-red-400 ml-1">×</button>
                </span>
              ))}
            </div>
          </div>

          {/* Severity + Category + Confidence + File Pattern */}
          <div className="grid grid-cols-4 gap-4 mb-4">
            <div>
              <label className="block text-xs text-dark-500 mb-1">{t.customRules.severity}</label>
              <select value={editing.severity} onChange={e => setEditing({ ...editing, severity: e.target.value })}
                className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2 text-white text-sm focus:outline-none focus:border-blue-500">
                <option value="critical">{t.severity.critical}</option>
                <option value="high">{t.severity.high}</option>
                <option value="medium">{t.severity.medium}</option>
                <option value="low">{t.severity.low}</option>
                <option value="info">{t.severity.info}</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-dark-500 mb-1">{t.customRules.category}</label>
              <select value={editing.category} onChange={e => setEditing({ ...editing, category: e.target.value })}
                className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2 text-white text-sm focus:outline-none focus:border-blue-500">
                <option value="backdoor">Backdoor</option>
                <option value="obfuscation">Obfuscation</option>
                <option value="webshell">Webshell</option>
                <option value="wordpress">WordPress</option>
                <option value="persistence">Persistence</option>
                <option value="redirect">Redirect</option>
                <option value="secrets">Secrets</option>
                <option value="injection">Injection</option>
                <option value="integrity">Integrity</option>
                <option value="security">Security</option>
                <option value="external-access">External Access</option>
                <option value="code-pattern">Code Pattern</option>
                <option value="file-analysis">File Analysis</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-dark-500 mb-1">{t.customRules.confidence || 'Confidence'}</label>
              <select value={editing.confidence || 'medium'} onChange={e => setEditing({ ...editing, confidence: e.target.value })}
                className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2 text-white text-sm focus:outline-none focus:border-blue-500">
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-dark-500 mb-1">{t.customRules.filePattern}</label>
              <input value={editing.filePattern || '*'} onChange={e => setEditing({ ...editing, filePattern: e.target.value })}
                className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2 text-white text-sm focus:outline-none focus:border-blue-500"
                placeholder="* or .php,.phtml" />
            </div>
          </div>

          {/* Recommendation */}
          <div className="mb-4">
            <label className="block text-xs text-dark-500 mb-1">{t.customRules.recommendation || 'Recommendation'}</label>
            <textarea value={editing.recommendation || ''} onChange={e => setEditing({ ...editing, recommendation: e.target.value })}
              className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2 text-white text-sm focus:outline-none focus:border-blue-500"
              rows={2} placeholder="Remediation advice for this rule..." />
          </div>

          {/* Tags */}
          <div className="mb-4">
            <label className="block text-xs text-dark-500 mb-1">{t.customRules.tags || 'Tags'}</label>
            <div className="flex gap-2 mb-2">
              <input value={newTag} onChange={e => setNewTag(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addTag()}
                className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-4 py-2 text-white text-sm focus:outline-none focus:border-blue-500"
                placeholder="e.g. wordpress, webshell, rce" />
              <button onClick={addTag} className="bg-dark-700 hover:bg-dark-600 text-white px-3 py-2 rounded-lg text-sm">+</button>
            </div>
            <div className="flex flex-wrap gap-1">
              {(editing.tags || []).map((tag, i) => (
                <span key={i} className="bg-green-500/10 text-green-400 px-2 py-1 rounded text-xs flex items-center gap-1">
                  #{tag}
                  <button onClick={() => removeTag(i)} className="text-green-300 hover:text-red-400 ml-1">×</button>
                </span>
              ))}
            </div>
          </div>

          {/* Regex + Enabled + Test */}
          <div className="flex items-center gap-6 mb-4">
            <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
              <input type="checkbox" checked={editing.isRegex !== false} onChange={e => setEditing({ ...editing, isRegex: e.target.checked })}
                className="w-4 h-4 rounded bg-dark-900 border-dark-600 text-blue-500 focus:ring-blue-500" />
              {t.customRules.isRegex}
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
              <input type="checkbox" checked={editing.enabled !== false} onChange={e => setEditing({ ...editing, enabled: e.target.checked })}
                className="w-4 h-4 rounded bg-dark-900 border-dark-600 text-blue-500 focus:ring-blue-500" />
              {t.customRules.enabled}
            </label>
            <div className="flex-1">
              <div className="flex gap-2">
                <input value={testInput} onChange={e => { setTestInput(e.target.value); setTestResult(null); }}
                  className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-3 py-1.5 text-white text-xs font-mono focus:outline-none focus:border-blue-500"
                  placeholder={t.customRules.testInput} />
                <button onClick={handleTest} className="bg-dark-700 hover:bg-dark-600 text-white px-3 py-1.5 rounded-lg text-xs">{t.customRules.testPattern}</button>
              </div>
              {testResult && (
                <div className={`mt-1 text-xs font-medium ${testResult === 'match' ? 'text-red-400' : 'text-green-400'}`}>
                  {testResult === 'match' ? t.customRules.matchFound : t.customRules.noMatch}
                </div>
              )}
            </div>
          </div>

          <div className="flex gap-2">
            <button onClick={handleSave} className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-lg text-sm font-medium transition-colors">{t.customRules.save}</button>
            <button onClick={() => { setShowForm(false); setEditing(emptyRule); }} className="bg-dark-700 hover:bg-dark-600 text-white px-6 py-2 rounded-lg text-sm transition-colors">{t.customRules.cancel}</button>
          </div>
        </div>
      )}

      {/* Category Filter Tabs */}
      <div className="flex gap-1 bg-dark-800 border border-dark-700 rounded-xl p-1 mb-4 overflow-x-auto">
        <button onClick={() => setCatFilter('all')}
          className={`px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${catFilter === 'all' ? 'bg-blue-600 text-white' : 'text-dark-500 hover:text-white hover:bg-dark-700'}`}>
          All ({rules.length})
        </button>
        {categories.map(([cat, count]) => (
          <button key={cat} onClick={() => setCatFilter(cat)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${catFilter === cat ? 'bg-blue-600 text-white' : 'text-dark-500 hover:text-white hover:bg-dark-700'}`}>
            <span className="flex-shrink-0">{categoryIcons[cat] || <IconCategory size={16} />}</span>
            <span>{cat}</span>
            <span className={`text-[10px] px-1 py-0.5 rounded-full ${catFilter === cat ? 'bg-blue-500/30' : 'bg-dark-700'}`}>{count}</span>
          </button>
        ))}
      </div>

      {/* Search */}
      <div className="flex gap-3 mb-4">
        <input type="text" value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search rules by name, ID, description, or tags..."
          className="flex-1 bg-dark-800 border border-dark-700 rounded-lg px-4 py-2.5 text-white placeholder:text-dark-600 focus:border-blue-500 focus:outline-none text-sm" />
        {search && <button onClick={() => setSearch('')} className="bg-dark-700 hover:bg-dark-600 text-white px-3 py-2 rounded-lg text-sm">✕</button>}
      </div>

      {/* Rule Cards */}
      <div className="space-y-3">
        {filteredRules.map(rule => (
          <div key={rule.id} className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
            <div className="px-5 py-4 flex items-center gap-3 cursor-pointer hover:bg-dark-700/50 transition-colors"
              onClick={() => setExpandedId(expandedId === rule.id ? null : rule.id)}>
              <span className="flex-shrink-0 text-dark-500">{categoryIcons[rule.category] || <IconCategory size={16} />}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-white font-medium">{rule.name}</span>
                  {rule.isBuiltin && <span className="text-[10px] px-1.5 py-0.5 rounded bg-dark-600 text-dark-500 flex items-center gap-1"><IconLock size={10} /> built-in</span>}
                </div>
                <div className="text-dark-500 text-xs mt-0.5 truncate">{rule.description}</div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs px-2 py-0.5 rounded border ${sevColors[rule.severity]}`}>{t.severity[rule.severity as keyof typeof t.severity] || rule.severity}</span>
                <span className={`text-xs px-2 py-0.5 rounded border ${confColors[rule.confidence] || confColors.medium}`}>{rule.confidence}</span>
              </div>
              <div className="flex gap-1">
                {(rule.tags || []).slice(0, 3).map(tag => (
                  <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded bg-dark-600 text-dark-400">#{tag}</span>
                ))}
                {(rule.tags || []).length > 3 && <span className="text-[10px] text-dark-500">+{rule.tags.length - 3}</span>}
              </div>
              <button onClick={(e) => { e.stopPropagation(); handleToggle(rule); }}
                className={`w-10 h-5 rounded-full transition-colors relative ${rule.enabled ? 'bg-blue-600' : 'bg-dark-600'}`}>
                <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${rule.enabled ? 'left-5' : 'left-0.5'}`} />
              </button>
              <span className="text-dark-500 text-sm">{expandedId === rule.id ? '▲' : '▼'}</span>
            </div>

            {expandedId === rule.id && (
              <div className="border-t border-dark-700 px-5 py-4 space-y-3">
                {/* Patterns */}
                <div>
                  <div className="text-xs text-dark-500 mb-1">{t.customRules.patterns || 'Patterns'}</div>
                  <div className="space-y-1">
                    {(rule.patterns && rule.patterns.length > 0 ? rule.patterns : [rule.pattern]).map((p, i) => (
                      <div key={i} className="bg-dark-900 rounded-lg px-3 py-1.5 font-mono text-xs text-blue-300">{p}</div>
                    ))}
                  </div>
                </div>

                {/* Path Patterns + Target Files */}
                <div className="grid grid-cols-2 gap-4">
                  {rule.pathPatterns && rule.pathPatterns.length > 0 && (
                    <div>
                      <div className="text-xs text-dark-500 mb-1">{t.customRules.pathPatterns || 'Path Patterns'}</div>
                      <div className="space-y-1">
                        {rule.pathPatterns.map((p, i) => (
                          <div key={i} className="bg-dark-900 rounded-lg px-3 py-1.5 font-mono text-xs text-purple-300">{p}</div>
                        ))}
                      </div>
                    </div>
                  )}
                  {rule.targetFiles && rule.targetFiles.length > 0 && (
                    <div>
                      <div className="text-xs text-dark-500 mb-1">{t.customRules.targetFiles || 'Target Files'}</div>
                      <div className="flex flex-wrap gap-1">
                        {rule.targetFiles.map((f, i) => (
                          <span key={i} className="bg-orange-500/10 text-orange-400 px-2 py-0.5 rounded text-xs font-mono">{f}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Recommendation */}
                {rule.recommendation && (
                  <div>
                    <div className="text-xs text-dark-500 mb-1">{t.customRules.recommendation || 'Recommendation'}</div>
                    <div className="bg-green-500/5 border border-green-500/20 rounded-lg px-4 py-2 text-sm text-green-300">{rule.recommendation}</div>
                  </div>
                )}

                {/* Meta */}
                <div className="flex items-center gap-4 text-xs text-dark-500">
                  <span>ID: <span className="text-gray-400 font-mono">{rule.id}</span></span>
                  <span>Type: <span className="text-gray-400">{rule.isRegex ? 'Regex' : 'String'}</span></span>
                  <span>File ext: <span className="text-gray-400">{rule.filePattern}</span></span>
                  <span>Check: <span className="text-gray-400">{rule.checkType}</span></span>
                </div>

                {/* Actions */}
                {!rule.isBuiltin && (
                  <div className="flex gap-2 pt-2 border-t border-dark-700/50">
                    <button onClick={() => handleEdit(rule)} className="text-blue-400 hover:text-blue-300 text-xs">{t.customRules.editRule}</button>
                    <button onClick={() => handleDelete(rule.id)} className="text-red-400 hover:text-red-300 text-xs">{t.customRules.delete}</button>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
        {filteredRules.length === 0 && <div className="text-center py-16 text-dark-500">{t.customRules.noRules}</div>}
      </div>
    </div>
  );
}
