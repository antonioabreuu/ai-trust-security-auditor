"use client";

import React, { useState, useEffect, useRef } from 'react';
import { Download, ShieldAlert, ShieldCheck, Activity, AlertTriangle, FileWarning, Fingerprint, Database, Terminal, Search, X } from 'lucide-react';

export default function Dashboard() {
  const [mounted, setMounted] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  
  const [auditResults, setAuditResults] = useState<any[]>([]);
  const [stats, setStats] = useState({ injections: 0, piiLeaks: 0, grounding: 0 });
  const [isAuditing, setIsAuditing] = useState(false);
  const [selectedPayload, setSelectedPayload] = useState<any | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [liveLogs, setLiveLogs] = useState<string[]>([
    "[INFO] Sistema iniciado. Aguardando comando de varredura..."
  ]);
  const [riskScore, setRiskScore] = useState(0);
  const [chartData, setChartData] = useState<{time: string, threats: number}[]>([]);
  const [severity, setSeverity] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [showAll, setShowAll] = useState(false);
  const [scanProfile, setScanProfile] = useState('full');

  // Simulated data state
  const hasData = auditResults.length > 0;

  const fetchAuditData = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8000/audit/pii-leak', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile: scanProfile })
      });
      const data = await response.json();
      
      console.log("Resposta do Scanner:", data);

      setAuditResults(data?.detalhes || []);
      
      if (data?.stats) {
        setStats({ 
          injections: data.stats.injection_attempts, 
          piiLeaks: data.stats.pii_leaks,
          grounding: data.stats.grounding_score
        });
        setRiskScore(data.stats.risk_score);
        setSeverity(data.stats.severity);
      }
      
      if (data?.timestamp_scan) {
        setChartData(prev => {
          const newChart = [...prev, { time: data.timestamp_scan, threats: data.vazamentos_detectados }];
          if (newChart.length > 20) return newChart.slice(newChart.length - 20);
          return newChart;
        });
      }

      return data;

    } catch (error) {
      console.error("Falha ao atualizar dashboard:", error);
    }
  };

  const runFullAudit = async () => {
    setIsAuditing(true);
    
    const startTime = new Date().toLocaleTimeString();
    setLiveLogs(prev => [...prev, `[INFO] [${startTime}] Iniciando auditoria de segurança (Perfil: ${scanProfile.toUpperCase()})...`]);
    
    try {
      setTimeout(() => {
        const time500 = new Date().toLocaleTimeString();
        setLiveLogs(prev => [...prev, `[INFO] [${time500}] Analisando requisições e respostas do modelo LLM base...`]);
      }, 500);

      // 1. Executa o teste de injeção (mantendo no backend)
      await fetch('http://127.0.0.1:8000/audit/prompt-injection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          target_name: "LLM_Alpha", 
          target_endpoint: "http://api.target.ai/v1" 
        })
      });

      // 2. Busca dados reais
      const data = await fetchAuditData();

      if (data) {
        setTimeout(() => {
          const time1200 = new Date().toLocaleTimeString();
          setLiveLogs(prev => [...prev, `[CRIT] [${time1200}] Análise finalizada: ${data.vazamentos_detectados} anomalias de segurança interceptadas.`]);
        }, 1200);

        setTimeout(() => {
          const time1500 = new Date().toLocaleTimeString();
          setLiveLogs(prev => [...prev, `[WARN] [${time1500}] Recalibrando Risco do Sistema para ${data.stats?.risk_score || 0}/100. Atualizando painel...`]);
          setIsAuditing(false);
        }, 1500);
      } else {
        setIsAuditing(false);
      }

    } catch (e) {
      console.error(e);
      setIsAuditing(false);
    }
  };

  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [liveLogs]);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return null;
  }

  const getRiskColor = (score: number) => {
    if (score < 40) return 'text-emerald-500 stroke-emerald-500';
    if (score < 70) return 'text-amber-500 stroke-amber-500';
    return 'text-crimson-500 stroke-crimson-500';
  };
  
  const getRiskBg = (score: number) => {
    if (score < 40) return 'bg-emerald-500/10 border-emerald-500/20';
    if (score < 70) return 'bg-amber-500/10 border-amber-500/20 shadow-[0_0_15px_rgba(245,158,11,0.15)]';
    return 'bg-crimson-500/10 border-crimson-500/20 shadow-[0_0_15px_rgba(239,68,68,0.15)]';
  };




  const filteredResults = auditResults.filter((result) => {
    if (!searchTerm) return true;
    
    // Normaliza o termo de busca (tudo em minúsculo) e separa por espaços para busca cruzada
    const searchLower = searchTerm.toLowerCase();
    const keywords = searchLower.split(" ").filter(k => k.trim() !== "");

    // Extrai os campos do result garantindo que não quebre se algo for undefined
    const id = (result.log_id || "").toLowerCase();
    const type = (result.achados_mascarados?.[0]?.type || "").toLowerCase();
    const evidence = (result.achados_mascarados?.[0]?.evidence || "").toLowerCase();
    const time = (result.timestamp || "").toLowerCase();

    // A linha só é exibida se TODAS as palavras digitadas forem encontradas em alguma das colunas (AND logic)
    return keywords.every(kw => 
      id.includes(kw) || 
      type.includes(kw) || 
      evidence.includes(kw) || 
      time.includes(kw)
    );
  });
  const maxSev = Math.max(severity.critical, severity.high, severity.medium, severity.low, 1);
  const getSevWidth = (v: number) => `${Math.max((v / maxSev) * 100, 2)}%`;

  return (
    <div suppressHydrationWarning className="min-h-screen bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-[#1A1C1E] via-[#0D0E10] to-[#0D0E10] text-foreground font-sans selection:bg-cyan-500/30">
      {/* Header */}
      <header className="border-b border-border/50 bg-[#0D0E10]/40 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldAlert className="w-6 h-6 text-cyan-400 drop-shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
            <h1 className="font-semibold text-lg tracking-wider text-white drop-shadow-md">AI TRUST & SECURITY AUDITOR</h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-400/10 text-cyan-400 border border-cyan-400/20 ml-2">SOC/GRC</span>
          </div>
          <div className="flex items-center gap-3">
            <select
              value={scanProfile}
              onChange={(e) => setScanProfile(e.target.value)}
              className="bg-[#0D0E10] text-cyan-300 text-xs font-mono border border-cyan-500/30 rounded px-3 py-2 outline-none cursor-pointer hover:bg-cyan-900/20 transition-colors"
            >
              <option className="bg-[#0D0E10] text-cyan-300 border border-cyan-500/30" value="full">Full Architecture Audit</option>
              <option className="bg-[#0D0E10] text-cyan-300 border border-cyan-500/30" value="pii">Data Privacy (PII/LGPD)</option>
              <option className="bg-[#0D0E10] text-cyan-300 border border-cyan-500/30" value="owasp">OWASP LLM Top 10</option>
            </select>
            <button 
              onClick={runFullAudit}
              disabled={isAuditing}
              className={`flex items-center gap-2 px-4 py-2 font-medium text-sm rounded transition-all shadow-[0_0_15px_rgba(6,182,212,0.4)] hover:shadow-[0_0_25px_rgba(6,182,212,0.6)] ${isAuditing ? 'bg-cyan-600 text-background/70 cursor-not-allowed' : 'bg-cyan-500 hover:bg-cyan-400 text-background'}`}
            >
              <Activity className={`w-4 h-4 ${isAuditing ? 'animate-spin' : ''}`} />
              {isAuditing ? 'AUDITANDO...' : 'EXECUTAR VARREDURA'}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8 animate-fade-in-up">
          
          {/* Top Section: Risk Score & Summary Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6" style={{ animationDelay: '0.1s' }}>
            
            {/* Risk Score */}
            <div className={`col-span-1 bg-surface/40 backdrop-blur-md border rounded-lg p-6 flex flex-col items-center justify-center relative overflow-hidden group transition-all duration-300 opacity-0 animate-fade-in-up ${getRiskBg(riskScore)}`} style={{ animationDelay: '0.1s' }}>
              <div className="absolute inset-0 bg-gradient-to-b from-transparent to-amber-500/5 opacity-0 group-hover:opacity-100 transition-opacity" />
              <h2 className="text-xs font-mono text-gray-400 uppercase tracking-widest mb-6 w-full text-left drop-shadow-sm">RISCO DO SISTEMA</h2>
              <div className="relative w-40 h-40 flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90 drop-shadow-[0_0_10px_rgba(245,158,11,0.5)]" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="42" fill="none" className="stroke-border/50" strokeWidth="8" />
                  {!isLoading && (
                    <circle
                      cx="50"
                      cy="50"
                      r="42"
                      fill="none"
                      className={`${getRiskColor(riskScore)} transition-all duration-1000 ease-out`}
                      strokeWidth="8"
                      strokeDasharray="264"
                      strokeDashoffset={264 - (264 * riskScore) / 100}
                      strokeLinecap="round"
                    />
                  )}
                </svg>
                <div className="absolute flex flex-col items-center justify-center">
                  {isLoading ? (
                    <div className="h-8 w-16 bg-surface-hover/50 animate-pulse rounded"></div>
                  ) : (
                    <span className={`text-4xl font-bold ${getRiskColor(riskScore).split(' ')[0]} drop-shadow-md`}>{riskScore}</span>
                  )}
                  <span className="text-xs text-gray-400 font-mono mt-1">/ 100</span>
                </div>
              </div>
              <div className={`mt-6 px-3 py-1 rounded-full border text-xs font-medium transition-colors ${riskScore < 40 ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.2)]' : riskScore < 70 ? 'bg-amber-500/10 border-amber-500/30 text-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.2)]' : 'bg-crimson-500/10 border-crimson-500/30 text-crimson-500 shadow-[0_0_10px_rgba(239,68,68,0.2)]'}`}>
                {riskScore < 40 ? 'Secure' : riskScore < 70 ? 'Moderate Risk' : 'Critical Risk'}
              </div>
            </div>

            {/* Metrics Cards */}
            <div className="col-span-1 lg:col-span-3 grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Injection Attempts */}
              <div className="bg-surface/40 backdrop-blur-md border border-border/50 rounded-lg p-6 flex flex-col justify-between hover:border-border transition-colors shadow-[0_0_20px_rgba(239,68,68,0.05)] hover:shadow-[0_0_25px_rgba(239,68,68,0.1)] relative overflow-hidden group opacity-0 animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
                <div className="absolute -right-10 -top-10 w-32 h-32 bg-crimson-500/10 rounded-full blur-3xl opacity-50 group-hover:opacity-100 transition-opacity"></div>
                <div className="flex justify-between items-start relative z-10">
                  <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wide">TENTATIVAS DE INJEÇÃO</h3>
                  <div className="p-2 bg-crimson-500/10 rounded-md border border-crimson-500/30 shadow-[0_0_10px_rgba(239,68,68,0.2)]">
                    <AlertTriangle className="w-4 h-4 text-crimson-500" />
                  </div>
                </div>
                <div className="mt-4 flex items-end justify-between relative z-10">
                  <div>
                    <div className="text-3xl font-bold text-white drop-shadow-sm">{stats.injections}</div>
                    <div className="text-xs font-mono mt-2 text-crimson-400">+18.5% ↑ <span className="text-gray-500 ml-1">last 24h</span></div>
                  </div>
                  <span className="px-2 py-1 text-[10px] uppercase font-bold tracking-wider rounded bg-crimson-500/10 text-crimson-500 border border-crimson-500/30 shadow-[0_0_8px_rgba(239,68,68,0.2)]">High</span>
                </div>
              </div>

              {/* PII Leaks */}
              <div className="bg-surface/40 backdrop-blur-md border border-border/50 rounded-lg p-6 flex flex-col justify-between hover:border-border transition-colors shadow-[0_0_20px_rgba(16,185,129,0.05)] hover:shadow-[0_0_25px_rgba(16,185,129,0.1)] relative overflow-hidden group opacity-0 animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
                <div className="absolute -right-10 -top-10 w-32 h-32 bg-emerald-500/10 rounded-full blur-3xl opacity-50 group-hover:opacity-100 transition-opacity"></div>
                <div className="flex justify-between items-start relative z-10">
                  <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wide">VAZAMENTOS DE PII</h3>
                  <div className="p-2 bg-emerald-500/10 rounded-md border border-emerald-500/30 shadow-[0_0_10px_rgba(16,185,129,0.2)]">
                    <ShieldCheck className="w-4 h-4 text-emerald-500" />
                  </div>
                </div>
                <div className="mt-4 flex items-end justify-between relative z-10">
                  <div>
                    <div className="text-3xl font-bold text-white drop-shadow-sm">{stats.piiLeaks}</div>
                    <div className="text-xs font-mono mt-2 text-emerald-400">-12.4% ↓ <span className="text-gray-500 ml-1">masked</span></div>
                  </div>
                  <span className="px-2 py-1 text-[10px] uppercase font-bold tracking-wider rounded bg-emerald-500/10 text-emerald-500 border border-emerald-500/30 shadow-[0_0_8px_rgba(16,185,129,0.2)]">Secure</span>
                </div>
              </div>

              {/* Grounding Score */}
              <div className="bg-surface/40 backdrop-blur-md border border-border/50 rounded-lg p-6 flex flex-col justify-between hover:border-border transition-colors shadow-[0_0_20px_rgba(6,182,212,0.05)] hover:shadow-[0_0_25px_rgba(6,182,212,0.1)] relative overflow-hidden group opacity-0 animate-fade-in-up" style={{ animationDelay: '0.4s' }}>
                <div className="absolute -right-10 -top-10 w-32 h-32 bg-cyan-400/10 rounded-full blur-3xl opacity-50 group-hover:opacity-100 transition-opacity"></div>
                <div className="flex justify-between items-start relative z-10">
                  <h3 className="text-sm font-mono text-gray-400 uppercase tracking-wide">PONTUAÇÃO DE GROUNDING</h3>
                  <div className="p-2 bg-cyan-400/10 rounded-md border border-cyan-400/30 shadow-[0_0_10px_rgba(6,182,212,0.2)]">
                    <Activity className="w-4 h-4 text-cyan-400" />
                  </div>
                </div>
                <div className="mt-4 flex items-end justify-between relative z-10">
                  <div>
                    <div className="text-3xl font-bold text-white drop-shadow-sm">{stats.grounding}%</div>
                    <div className="text-xs font-mono mt-2 text-amber-400">-1.2% ↓ <span className="text-gray-500 ml-1">avg similarity</span></div>
                  </div>
                  <span className="px-2 py-1 text-[10px] uppercase font-bold tracking-wider rounded bg-emerald-500/10 text-emerald-500 border border-emerald-500/30 shadow-[0_0_8px_rgba(16,185,129,0.2)]">Pass</span>
                </div>
              </div>
            </div>
          </div>

          {/* Charts & Graphs Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Threat Activity over Time */}
            <div className="col-span-1 lg:col-span-2 bg-surface/40 backdrop-blur-md border border-border/50 rounded-lg p-6 shadow-[0_4px_20px_rgba(0,0,0,0.2)] relative overflow-hidden opacity-0 animate-fade-in-up transition-all duration-300 hover:-translate-y-1 hover:border-cyan-500/50 hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]" style={{ animationDelay: '0.5s' }}>
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 to-transparent pointer-events-none" />
              <div className="flex justify-between items-center mb-6 relative z-10">
                <h3 className="text-sm font-mono text-gray-300 uppercase tracking-wide">ATIVIDADE DE AMEAÇAS NO TEMPO</h3>
                <span className="text-xs font-mono text-cyan-400 border border-cyan-400/20 px-2 py-0.5 rounded bg-cyan-400/10">Live 24h</span>
              </div>
              
              {isLoading ? (
                <div className="h-40 w-full bg-surface-hover/30 animate-pulse rounded-lg border border-border/50 flex items-center justify-center">
                  <div className="h-2 w-full max-w-[80%] bg-surface-hover/80 rounded-full animate-pulse"></div>
                </div>
              ) : (
                <div className="h-40 w-full relative flex items-end group animate-fade-in-up">
                  {/* Background Grid */}
                  <div className="absolute inset-0 grid grid-cols-6 grid-rows-4 opacity-10">
                    {Array.from({length: 24}).map((_, i) => (
                      <div key={i} className="border-l border-t border-cyan-500"></div>
                    ))}
                  </div>
                  
                  <div className="w-full h-full relative z-10 flex items-end gap-2 px-2 pb-1">
                    {chartData.length === 0 ? (
                      <div className="w-full h-full flex items-center justify-center text-xs font-mono text-gray-500">Nenhum dado de varredura ainda.</div>
                    ) : (
                      chartData.map((item, i) => {
                        const maxThreats = Math.max(...chartData.map(d => d.threats), 10);
                        const heightPct = Math.max((item.threats / maxThreats) * 100, 5);
                        const isHighRisk = item.threats >= 5;
                        return (
                          <div 
                            key={i} 
                            title={`${item.time}: ${item.threats} ameaças`}
                            className={`flex-1 rounded-t-sm transition-all duration-500 hover:opacity-80 cursor-pointer ${isHighRisk ? 'bg-crimson-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]' : 'bg-cyan-500 shadow-[0_0_10px_rgba(6,182,212,0.5)]'}`}
                            style={{ height: `${heightPct}%` }}
                          />
                        );
                      })
                    )}
                  </div>
              </div>
            )}
          </div>

          {/* Severity Heatmap */}
          <div className="col-span-1 bg-surface/40 backdrop-blur-md border border-border/50 rounded-lg p-6 shadow-[0_4px_20px_rgba(0,0,0,0.2)] flex flex-col justify-between opacity-0 animate-fade-in-up" style={{ animationDelay: '0.6s' }}>
            <h3 className="text-sm font-mono text-gray-300 uppercase tracking-wide mb-6">DISTRIBUIÇÃO DE GRAVIDADE</h3>
            
            {isLoading ? (
              <div className="space-y-6">
                {[1, 2, 3, 4].map((i) => (
                  <div key={i} className="w-full h-3 bg-surface-hover/30 animate-pulse rounded-full"></div>
                ))}
              </div>
            ) : (
              <div className="space-y-5 animate-fade-in-up">
                <div>
                  <div className="flex justify-between text-xs font-mono mb-1.5">
                    <span className="text-crimson-400">Critical</span>
                    <span className="text-gray-400">{severity.critical}</span>
                  </div>
                  <div className="w-full h-2 bg-surface rounded-full overflow-hidden border border-border/50">
                    <div className="h-full bg-crimson-500 shadow-[0_0_10px_rgba(239,68,68,0.8)] relative transition-all duration-1000" style={{ width: getSevWidth(severity.critical) }}>
                      <div className="absolute inset-0 bg-white/20 animate-[pulse_2s_ease-in-out_infinite]"></div>
                    </div>
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono mb-1.5">
                    <span className="text-amber-400">High</span>
                    <span className="text-gray-400">{severity.high}</span>
                  </div>
                  <div className="w-full h-2 bg-surface rounded-full overflow-hidden border border-border/50">
                    <div className="h-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.6)] transition-all duration-1000" style={{ width: getSevWidth(severity.high) }}></div>
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono mb-1.5">
                    <span className="text-emerald-400">Medium</span>
                    <span className="text-gray-400">{severity.medium}</span>
                  </div>
                  <div className="w-full h-2 bg-surface rounded-full overflow-hidden border border-border/50">
                    <div className="h-full bg-emerald-500 transition-all duration-1000" style={{ width: getSevWidth(severity.medium) }}></div>
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono mb-1.5">
                    <span className="text-gray-300">Low</span>
                    <span className="text-gray-400">{severity.low}</span>
                  </div>
                  <div className="w-full h-2 bg-surface rounded-full overflow-hidden border border-border/50">
                    <div className="h-full bg-gray-500 transition-all duration-1000" style={{ width: getSevWidth(severity.low) }}></div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* AI Search Bar */}
        <div className="relative opacity-0 animate-fade-in-up" style={{ animationDelay: '0.7s' }}>
          <Search className="absolute left-4 top-3.5 h-5 w-5 text-cyan-400 drop-shadow-[0_0_5px_rgba(6,182,212,0.5)]" />
          <input 
            type="text" 
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filtrar achados (ex: 'cpf', 'email', 'aws_key')..."
            className="w-full bg-[#111415]/60 backdrop-blur-md border border-cyan-500/20 rounded-lg pl-12 pr-4 py-3 text-sm text-gray-200 placeholder:text-gray-600 focus:outline-none focus:border-cyan-400 focus:shadow-[0_0_20px_rgba(6,182,212,0.15)] transition-all font-mono"
          />
        </div>

        {/* Findings & Logs Row */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 opacity-0 animate-fade-in-up" style={{ animationDelay: '0.8s' }}>
          
          {/* Findings Table */}
          <div className="col-span-1 xl:col-span-2 bg-surface/40 backdrop-blur-md border border-border/50 rounded-lg overflow-hidden shadow-[0_4px_20px_rgba(0,0,0,0.2)]">
            <div className="p-5 border-b border-border/50 flex justify-between items-center bg-surface-hover/30">
              <h2 className="text-sm font-mono text-gray-300 uppercase tracking-widest">DESCOBERTAS RECENTES DE SEGURANÇA</h2>
              <button onClick={() => setShowAll(!showAll)} className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors font-mono uppercase">{showAll ? 'RECOLHER LOGS' : 'VER TODOS OS LOGS'}</button>
            </div>
            <div className="overflow-x-auto min-h-[200px]">
              {isLoading ? (
                <div className="p-6 space-y-4">
                  {[1, 2, 3, 4].map((i) => (
                    <div key={i} className="w-full h-10 bg-surface-hover/30 animate-pulse rounded-md border border-border/50"></div>
                  ))}
                </div>
              ) : (
                <table className="w-full text-left border-collapse animate-fade-in-up">
                  <thead>
                    <tr className="bg-background/20 border-b border-border/50">
                      <th className="px-6 py-4 text-xs font-mono text-gray-500 uppercase tracking-wider font-medium">Event ID</th>
                      <th className="px-6 py-4 text-xs font-mono text-gray-500 uppercase tracking-wider font-medium">Type</th>
                      <th className="px-6 py-4 text-xs font-mono text-gray-500 uppercase tracking-wider font-medium">Evidence</th>
                      <th className="px-6 py-4 text-xs font-mono text-gray-500 uppercase tracking-wider font-medium">Time</th>
                      <th className="px-6 py-4 text-xs font-mono text-gray-500 uppercase tracking-wider font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/50">
                    {filteredResults.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-6 py-12 text-center text-sm font-mono text-gray-500 bg-surface-hover/10">
                          {searchTerm ? "Nenhum resultado encontrado para a pesquisa." : "Aguardando execução da auditoria..."}
                        </td>
                      </tr>
                    ) : (
                      (showAll ? filteredResults : filteredResults.slice(0, 4)).map((finding) => {
                        const eventId = finding.log_id || 'unknown';
                        const eventType = finding.achados_mascarados?.[0]?.type || 'UNKNOWN';
                        const evidence = finding.achados_mascarados?.[0]?.evidence || 'N/A';
                        const eventTime = finding.timestamp ? new Date(finding.timestamp).toLocaleString() : 'N/A';

                        return (
                          <tr key={eventId} className="hover:bg-surface-hover/40 transition-colors group">
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className="text-sm font-mono text-gray-400 group-hover:text-cyan-400 transition-colors">{eventId}</span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className="px-2.5 py-1 text-[10px] font-mono font-medium rounded-full border text-amber-500 bg-amber-500/10 border-amber-500/30 uppercase tracking-wider shadow-[0_0_8px_rgba(245,158,11,0.15)]">
                                {eventType}
                              </span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className="text-sm text-gray-300 font-mono bg-[#0D0E10] px-2.5 py-1 rounded border border-border/50 shadow-inner">
                                {evidence}
                              </span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                              {eventTime}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <button 
                                onClick={() => setSelectedPayload(finding)}
                                className="text-[10px] text-cyan-400 hover:text-cyan-300 transition-colors font-mono uppercase bg-cyan-500/10 hover:bg-cyan-500/20 px-3 py-1.5 rounded border border-cyan-500/30 flex items-center gap-1 shadow-[0_0_10px_rgba(6,182,212,0.1)]">
                                VER PAYLOAD
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Live Audit Log Stream */}
          <div className="col-span-1 bg-[#0A0A0C]/80 backdrop-blur-md border border-border/50 rounded-lg overflow-hidden shadow-[0_4px_20px_rgba(0,0,0,0.4)] flex flex-col relative min-h-[250px]">
            <div className="p-3 border-b border-border/50 flex items-center gap-2 bg-[#111415]/80">
              <Terminal className="w-4 h-4 text-gray-400" />
              <h3 className="text-xs font-mono text-gray-300 uppercase tracking-widest">LOG DE AUDITORIA AO VIVO</h3>
              <div className="ml-auto w-2 h-2 bg-emerald-500 rounded-full animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]"></div>
            </div>
            
            {isLoading ? (
              <div className="p-4 space-y-3 flex-1">
                {[1, 2, 3, 4, 5].map((i) => (
                  <div key={i} className={`h-2 bg-surface-hover/30 animate-pulse rounded-full ${i % 2 === 0 ? 'w-3/4' : 'w-full'}`}></div>
                ))}
              </div>
            ) : (
              <div className="p-4 space-y-2 font-mono text-[11px] leading-tight flex-1 overflow-auto relative animate-fade-in-up custom-scrollbar">
                {liveLogs.map((log, i) => {
                  let colorClass = "text-gray-400";
                  if (log.includes("[WARN]")) colorClass = "text-amber-400";
                  if (log.includes("[CRIT]")) colorClass = "text-crimson-400 drop-shadow-[0_0_5px_rgba(239,68,68,0.5)]";
                  if (log.includes("[INFO]")) colorClass = "text-cyan-200/70";
                  
                  return (
                    <div key={i} className={`${colorClass} opacity-90 break-words`}>
                      {log}
                    </div>
                  );
                })}
                <div ref={logsEndRef} />
                {/* Fade out bottom */}
                <div className="absolute bottom-0 left-0 right-0 h-16 bg-gradient-to-t from-[#0A0A0C] to-transparent pointer-events-none" />
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Drill-Down Modal */}
      {selectedPayload && (
        <div className="bg-black/80 backdrop-blur-sm fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in-up">
          <div className="bg-[#0D0E10] border border-cyan-500/30 w-full max-w-2xl rounded-lg p-6 shadow-[0_0_30px_rgba(6,182,212,0.15)] relative flex flex-col max-h-[90vh]">
            <div className="flex justify-between items-center mb-4 border-b border-border/50 pb-3">
              <h3 className="font-mono text-cyan-400 text-lg uppercase tracking-wider flex items-center gap-2">
                <Terminal className="w-5 h-5" />
                Payload Details: {selectedPayload.log_id || 'Event'}
              </h3>
              <button 
                onClick={() => setSelectedPayload(null)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
            <div className="overflow-auto flex-1 flex flex-col gap-4 font-mono text-sm">
              {selectedPayload.raw_payload ? (
                <>
                  {/* Seção Superior */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-surface/50 border border-border/50 p-3 rounded">
                      <span className="text-gray-500 text-xs uppercase block mb-1">Source IP</span>
                      <span className="text-gray-200">{selectedPayload.raw_payload.source_ip || 'N/A'}</span>
                    </div>
                    <div className="bg-surface/50 border border-border/50 p-3 rounded">
                      <span className="text-gray-500 text-xs uppercase block mb-1">Endpoint</span>
                      <span className="text-gray-200">{selectedPayload.raw_payload.endpoint || 'N/A'}</span>
                    </div>
                    <div className="bg-surface/50 border border-border/50 p-3 rounded">
                      <span className="text-gray-500 text-xs uppercase block mb-1">Triggered Rule</span>
                      <span className="text-amber-400 font-bold">{selectedPayload.raw_payload.triggered_rule || 'N/A'}</span>
                    </div>
                    <div className="bg-surface/50 border border-border/50 p-3 rounded">
                      <span className="text-gray-500 text-xs uppercase block mb-1">AI Action</span>
                      <span className={`${
                        selectedPayload.raw_payload.ai_response_action === 'BLOCKED' ? 'text-red-500 font-bold' : 
                        selectedPayload.raw_payload.ai_response_action === 'FLAGGED_FOR_REVIEW' ? 'text-yellow-500 font-bold' : 
                        'text-cyan-300 font-bold'
                      }`}>{selectedPayload.raw_payload.ai_response_action || 'N/A'}</span>
                    </div>
                  </div>

                  {/* Seção Inferior */}
                  <div className="bg-black/50 border border-cyan-500/20 p-4 rounded flex-1">
                    <span className="text-cyan-500/50 text-xs uppercase block mb-2">Conteúdo da Requisição (Prompt)</span>
                    <p className="text-cyan-300 whitespace-pre-wrap break-words leading-relaxed text-[13px]">
                      {selectedPayload.raw_payload.user_prompt || 'N/A'}
                    </p>
                  </div>
                </>
              ) : (
                <pre className="text-[11px] text-cyan-300 bg-black/50 p-4 rounded font-mono border border-cyan-500/10 whitespace-pre-wrap break-words">
                  {JSON.stringify(selectedPayload, null, 2)}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
