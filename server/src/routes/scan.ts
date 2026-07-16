import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { runScan } from '../scanner/engine';
import { extractZip, cleanupTemp } from '../scanner/zip-handler';
import { saveScan, getScan, deleteScan, updateScan, getHistory, getStats, getTrendData } from '../db/database';
import { generatePdfReport } from '../scanner/pdf-report';

const router = Router();
const upload = multer({ dest: path.join(__dirname, '..', '..', 'uploads'), limits: { fileSize: 200 * 1024 * 1024 } });

// POST /api/scan - Scan from directory path
router.post('/scan', (req: Request, res: Response) => {
  try {
    const { path: targetPath } = req.body;
    if (!targetPath || !fs.existsSync(targetPath)) {
      return res.status(400).json({ error: 'Invalid path or path does not exist' });
    }
    if (!fs.statSync(targetPath).isDirectory()) {
      return res.status(400).json({ error: 'Path is not a directory' });
    }

    const summary = runScan(targetPath, 'path');
    saveScan(summary);

    return res.json(summary);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/upload - Upload ZIP and scan
router.post('/upload', upload.single('file'), (req: Request, res: Response) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const extractedDir = extractZip(req.file.path);
    const summary = runScan(extractedDir, 'upload');
    summary.targetName = req.file.originalname;
    saveScan(summary);

    // Cleanup
    try { fs.unlinkSync(req.file.path); } catch {}
    cleanupTemp(extractedDir);

    return res.json(summary);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/scan/:id - Get scan result
router.get('/scan/:id', (req: Request, res: Response) => {
  const scan = getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  return res.json(scan);
});

// DELETE /api/scan/:id - Delete scan
router.delete('/scan/:id', (req: Request, res: Response) => {
  const deleted = deleteScan(req.params.id);
  if (!deleted) return res.status(404).json({ error: 'Scan not found' });
  return res.json({ success: true });
});

// GET /api/history - Get scan history
router.get('/history', (req: Request, res: Response) => {
  const limit = parseInt(req.query.limit as string) || 50;
  const offset = parseInt(req.query.offset as string) || 0;
  const history = getHistory(limit, offset);
  return res.json(history);
});

// GET /api/stats - Get dashboard stats
router.get('/stats', (req: Request, res: Response) => {
  const stats = getStats();
  return res.json(stats);
});

// GET /api/trend - Get trend data for charts
router.get('/trend', (_req: Request, res: Response) => {
  const trend = getTrendData();
  return res.json(trend);
});

// POST /api/compare - Compare two scans
router.post('/compare', (req: Request, res: Response) => {
  try {
    const { scanId1, scanId2 } = req.body;
    const scan1 = getScan(scanId1);
    const scan2 = getScan(scanId2);

    if (!scan1 || !scan2) return res.status(404).json({ error: 'One or both scans not found' });

    const comparison = {
      scan1: { id: scan1.id, name: scan1.targetName, date: scan1.scanDate, findings: scan1.totalFindings, severity: scan1.bySeverity },
      scan2: { id: scan2.id, name: scan2.targetName, date: scan2.scanDate, findings: scan2.totalFindings, severity: scan2.bySeverity },
      diff: {
        findingsDelta: scan2.totalFindings - scan1.totalFindings,
        criticalDelta: scan2.bySeverity.critical - scan1.bySeverity.critical,
        highDelta: scan2.bySeverity.high - scan1.bySeverity.high,
        mediumDelta: scan2.bySeverity.medium - scan1.bySeverity.medium,
        lowDelta: scan2.bySeverity.low - scan1.bySeverity.low,
        infoDelta: scan2.bySeverity.info - scan1.bySeverity.info,
      },
    };

    return res.json(comparison);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/report/:id/:format - Download report
router.get('/report/:id/:format', async (req: Request, res: Response) => {
  const scan = getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const format = req.params.format;
  const reportDir = path.join(__dirname, '..', '..', 'reports');
  if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });

  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="wp-sentinel-${scan.id}.json"`);
    return res.json(scan);
  }

  if (format === 'csv') {
    const rows = ['Severity,Category,Check ID,Check Name,File,Line,Message,Code,Details'];
    for (const r of scan.results) {
      for (const finding of r.findings) {
        rows.push([r.severity, r.category, r.checkId, r.checkName, `"${finding.file}"`, finding.line, `"${finding.message.replace(/"/g, '""')}"`, `"${finding.code.replace(/"/g, '""').substring(0, 100)}"`, `"${finding.details.replace(/"/g, '""').substring(0, 200)}"`].join(','));
      }
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="wp-sentinel-${scan.id}.csv"`);
    return res.send(rows.join('\n'));
  }

  if (format === 'html') {
    const sevColors: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#06b6d4', info: '#6b7280' };
    let findingsHtml = '';
    for (const result of scan.results) {
      if (result.findings.length === 0) continue;
      findingsHtml += `<div style="background:#1e293b;border:1px solid #334155;border-radius:8px;margin:12px 0;padding:16px;border-left:4px solid ${sevColors[result.severity]}">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
          <span style="background:${sevColors[result.severity]};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">${result.severity.toUpperCase()}</span>
          <span style="color:#94a3b8;font-size:12px">${result.checkId}</span>
          <span style="color:#f8fafc;font-weight:600">${result.checkName}</span>
          <span style="color:#64748b;margin-left:auto;font-size:12px">${result.findings.length} findings</span>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <tr style="background:#0f172a"><th style="padding:6px 12px;text-align:left;color:#94a3b8">File</th><th style="padding:6px 12px;text-align:left;color:#94a3b8">Line</th><th style="padding:6px 12px;text-align:left;color:#94a3b8">Message</th></tr>`;
      for (const f of result.findings) {
        findingsHtml += `<tr style="border-top:1px solid #1e293b"><td style="padding:6px 12px;color:#7dd3fc;font-family:monospace;font-size:12px">${f.file}</td><td style="padding:6px 12px;color:#94a3b8">${f.line}</td><td style="padding:6px 12px;color:#e2e8f0">${f.message}</td></tr>`;
      }
      findingsHtml += `</table></div>`;
    }

    const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WP-SENTINEL Report - ${scan.targetName}</title>
    <style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}.container{max-width:1000px;margin:0 auto}h1{color:#3b82f6;margin-bottom:4px}.sub{color:#64748b;margin-bottom:24px}.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}.stat{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px;text-align:center}.stat-val{font-size:28px;font-weight:bold;color:#3b82f6}.stat-lbl{color:#64748b;font-size:12px;margin-top:4px}</style></head>
    <body><div class="container"><h1>WP-SENTINEL Report</h1><p class="sub">${scan.targetName} | ${scan.scanDate} | ${scan.duration}ms</p>
    <div class="stats">
      <div class="stat"><div class="stat-val">${scan.totalFiles}</div><div class="stat-lbl">Total Files</div></div>
      <div class="stat"><div class="stat-val">${scan.phpFiles}</div><div class="stat-lbl">PHP Files</div></div>
      <div class="stat"><div class="stat-val" style="color:#ef4444">${scan.bySeverity.critical}</div><div class="stat-lbl">Critical</div></div>
      <div class="stat"><div class="stat-val" style="color:#f97316">${scan.bySeverity.high}</div><div class="stat-lbl">High</div></div>
      <div class="stat"><div class="stat-val">${scan.totalFindings}</div><div class="stat-lbl">Total Findings</div></div>
    </div>${findingsHtml}</div></body></html>`;

    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', `attachment; filename="wp-sentinel-${scan.id}.html"`);
    return res.send(html);
  }

  if (format === 'pdf') {
    try {
      const pdfBuffer = await generatePdfReport(scan);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="wp-sentinel-${scan.id}.pdf"`);
      return res.send(pdfBuffer);
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to generate PDF: ' + err.message });
    }
  }

  return res.status(400).json({ error: 'Invalid format. Use: json, csv, html, pdf' });
});

export default router;
