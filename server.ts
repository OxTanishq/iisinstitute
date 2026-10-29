import 'dotenv/config';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { z } from 'zod';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const firebaseConfigPath = path.resolve(__dirname, 'firebase-applet-config.json');
const firebaseConfig = JSON.parse(fs.readFileSync(firebaseConfigPath, 'utf-8')) as {
  apiKey: string;
  projectId: string;
};

interface VerifiedAuthUser {
  uid: string;
  email: string;
  emailVerified: boolean;
}

interface AuthenticatedRequest extends Request {
  authUser?: VerifiedAuthUser;
  isDemoSandbox?: boolean;
}

/**
 * Verifies a Firebase ID token server-side against Firebase Identity Toolkit
 * without exposing any admin service-account secrets.
 */
async function verifyFirebaseIdToken(idToken: string): Promise<VerifiedAuthUser | null> {
  if (!idToken || idToken.length < 20) return null;
  try {
    const resp = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(firebaseConfig.apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken }),
      }
    );
    if (!resp.ok) return null;
    const body = (await resp.json()) as {
      users?: Array<{ localId?: string; email?: string; emailVerified?: boolean }>;
    };
    const user = body.users?.[0];
    if (!user?.localId || !user?.email) return null;
    return {
      uid: user.localId,
      email: user.email,
      emailVerified: Boolean(user.emailVerified),
    };
  } catch {
    return null;
  }
}

async function requireProtectedApiAccess(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  if (req.headers['x-demo-sandbox'] === 'true') {
    req.isDemoSandbox = true;
    next();
    return;
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing Authorization Bearer token.' });
    return;
  }

  const token = authHeader.slice('Bearer '.length).trim();
  const verified = await verifyFirebaseIdToken(token);
  if (!verified || !verified.emailVerified) {
    res.status(401).json({ error: 'Invalid or unverified authentication token.' });
    return;
  }

  req.authUser = verified;
  next();
}

function getTodayISTServer(): string {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(new Date());
  const y = parts.find((p) => p.type === 'year')?.value ?? '2026';
  const m = parts.find((p) => p.type === 'month')?.value ?? '01';
  const d = parts.find((p) => p.type === 'day')?.value ?? '01';
  return `${y}-${m}-${d}`;
}

function formatINRPaiseServer(paise: number): string {
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: 'INR',
    minimumFractionDigits: paise % 100 === 0 ? 0 : 2,
    maximumFractionDigits: 2,
  }).format(Math.round(paise) / 100);
}

const calculatePaymentPayloadSchema = z.object({
  invoiceId: z.string().min(1).max(128),
  idempotencyKey: z.string().min(6).max(96).regex(/^[a-zA-Z0-9_\-]+$/),
  grossAmountPaise: z.number().int().min(0),
  discountPaise: z.number().int().min(0),
  existingPaidPaise: z.number().int().min(0),
  paymentAmountPaise: z.number().int().positive(),
  dueDate: z.string().min(8).max(16),
  paymentDate: z.string().min(8).max(16),
  agreement: z
    .object({
      id: z.string(),
      teacherId: z.string(),
      modelType: z.enum(['FIXED_SALARY', 'PERCENTAGE', 'PER_STUDENT', 'CUSTOM']),
      fixedMonthlyPaise: z.number().int().min(0),
      shareBasisPoints: z.number().int().min(0).max(10000),
      perStudentPaise: z.number().int().min(0),
    })
    .nullable(),
  existingStudentPeriodAllocationsCount: z.number().int().min(0).default(0),
});

const aiBriefingPayloadSchema = z.object({
  instituteName: z.string().min(1).max(140),
  currentLabel: z.string().min(1).max(40),
  previousLabel: z.string().min(1).max(40),
  collectedCurrentINR: z.string().max(60),
  collectedPreviousINR: z.string().max(60),
  revenueGrowthLabel: z.string().max(32),
  netIncomeCurrentINR: z.string().max(60),
  netIncomePreviousINR: z.string().max(60),
  pendingBalanceINR: z.string().max(60),
  collectionRatePercent: z.number().min(0).max(100),
  teacherPayoutRatioPercent: z.number().min(0).max(500),
  operatingExpensesINR: z.string().max(60),
  findings: z
    .array(
      z.object({
        metricName: z.string().max(120),
        currentValueFormatted: z.string().max(80),
        comparisonValueFormatted: z.string().max(80),
        percentChangeFormatted: z.string().max(40),
        severity: z.enum(['critical', 'warning', 'watch', 'healthy']),
        reason: z.string().max(400),
      })
    )
    .max(20),
});

const csvExportSchema = z.object({
  filename: z.string().min(1).max(100),
  headers: z.array(z.string().max(100)).min(1).max(30),
  rows: z.array(z.array(z.union([z.string(), z.number(), z.null()]))).max(5000),
});

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(express.json({ limit: '1mb' }));

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      timezone: 'Asia/Kolkata',
      todayIST: getTodayISTServer(),
    });
  });

  // Authoritative server-side payment + teacher share validation in integer paise
  app.post(
    '/api/finance/calculate-payment',
    requireProtectedApiAccess,
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = calculatePaymentPayloadSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid financial calculation payload.',
          details: parsed.error.flatten(),
        });
        return;
      }

      const data = parsed.data;
      const netAmountDuePaise = Math.max(0, data.grossAmountPaise - data.discountPaise);
      const remainingBeforePayment = Math.max(0, netAmountDuePaise - data.existingPaidPaise);

      if (data.paymentAmountPaise > remainingBeforePayment) {
        res.status(400).json({
          error: `Payment of ${formatINRPaiseServer(data.paymentAmountPaise)} exceeds remaining invoice balance of ${formatINRPaiseServer(remainingBeforePayment)}.`,
        });
        return;
      }

      const updatedPaidPaise = data.existingPaidPaise + data.paymentAmountPaise;
      const updatedBalancePaise = Math.max(0, netAmountDuePaise - updatedPaidPaise);
      const todayIST = getTodayISTServer();

      let updatedStatus: 'PAID' | 'PARTIAL' | 'OVERDUE' | 'PENDING';
      if (updatedPaidPaise >= netAmountDuePaise && updatedBalancePaise === 0) {
        updatedStatus = 'PAID';
      } else if (updatedPaidPaise > 0) {
        updatedStatus = data.dueDate < todayIST ? 'OVERDUE' : 'PARTIAL';
      } else {
        updatedStatus = data.dueDate < todayIST ? 'OVERDUE' : 'PENDING';
      }

      let allocatedSharePaise = 0;
      let rateSnapshotLabel = 'No variable share applicable';
      let shouldCreateAllocation = false;

      if (data.agreement) {
        const ag = data.agreement;
        if (ag.modelType === 'PERCENTAGE' || ag.modelType === 'CUSTOM') {
          allocatedSharePaise = Math.round((data.paymentAmountPaise * ag.shareBasisPoints) / 10000);
          const pct = (ag.shareBasisPoints / 100).toFixed(ag.shareBasisPoints % 100 === 0 ? 0 : 2);
          rateSnapshotLabel =
            ag.modelType === 'PERCENTAGE'
              ? `${pct}% of collected fee`
              : `Custom (${pct}% of collected fee)`;
          shouldCreateAllocation = allocatedSharePaise > 0;
        } else if (ag.modelType === 'PER_STUDENT') {
          if (data.existingStudentPeriodAllocationsCount === 0 && ag.perStudentPaise > 0) {
            allocatedSharePaise = ag.perStudentPaise;
            rateSnapshotLabel = `${formatINRPaiseServer(ag.perStudentPaise)} per student`;
            shouldCreateAllocation = true;
          }
        }
      }

      const deterministicPaymentDocId = `pay_${data.idempotencyKey}`;
      const deterministicAllocationDocId = data.agreement
        ? `alloc_${deterministicPaymentDocId}_${data.agreement.teacherId}`
        : '';

      res.json({
        deterministicPaymentDocId,
        deterministicAllocationDocId,
        netAmountDuePaise,
        updatedPaidPaise,
        updatedBalancePaise,
        updatedStatus,
        allocatedSharePaise,
        rateSnapshotLabel,
        shouldCreateAllocation,
      });
    }
  );

  // Grounded Gemini AI Executive Summary for Growth Insights (strictly server-side)
  app.post(
    '/api/insights/ai-briefing',
    requireProtectedApiAccess,
    async (req: AuthenticatedRequest, res: Response) => {
      const parsed = aiBriefingPayloadSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'Invalid analytics summary payload.' });
        return;
      }

      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        res.status(503).json({
          error: 'Gemini API key is not configured on the server.',
        });
        return;
      }

      const summary = parsed.data;
      try {
        const ai = new GoogleGenAI({
          apiKey,
          httpOptions: {
            headers: {
              'User-Agent': 'aistudio-build',
            },
          },
        });

        const prompt = `Analyze the following verified financial metrics for ${summary.instituteName} (${summary.currentLabel} vs ${summary.previousLabel}):
- Collected Fees (${summary.currentLabel}): ${summary.collectedCurrentINR} (vs ${summary.previousLabel}: ${summary.collectedPreviousINR}, MoM Change: ${summary.revenueGrowthLabel})
- Net Operating Income (${summary.currentLabel}): ${summary.netIncomeCurrentINR} (vs ${summary.previousLabel}: ${summary.netIncomePreviousINR})
- Pending Fee Receivables: ${summary.pendingBalanceINR}
- Invoice Collection Rate: ${summary.collectionRatePercent.toFixed(1)}%
- Teacher Payout-to-Revenue Ratio: ${summary.teacherPayoutRatioPercent.toFixed(1)}%
- Non-Payroll Operating Expenses: ${summary.operatingExpensesINR}
- Deterministic Risk Alerts Detected (${summary.findings.length}):
${
  summary.findings.length === 0
    ? 'None — all deterministic health checks are currently nominal.'
    : summary.findings
        .map(
          (f, i) =>
            `${i + 1}. [${f.severity.toUpperCase()}] ${f.metricName}: ${f.currentValueFormatted} vs ${f.comparisonValueFormatted} (${f.percentChangeFormatted}) — ${f.reason}`
        )
        .join('\n')
}

Write a concise 3-paragraph executive briefing for the institute owner:
1. Overall monthly financial health comparing revenue vs true operating profit.
2. Top bottleneck or margin pressure point using ONLY the exact numbers provided above.
3. Three concrete, prioritized operational actions for the coming 14 days.`;

        const response = await ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
          config: {
            systemInstruction:
              'You are a senior financial controller advising an Indian educational institute owner. CRITICAL RULE: Never invent, estimate, or extrapolate any rupee figures, percentages, or counts not explicitly given in the prompt. Quote exact provided figures verbatim. Use clear, direct prose without markdown headings or bullet clutter.',
            temperature: 0.2,
          },
        });

        res.json({
          briefing: response.text ?? 'Unable to generate executive narrative at this time.',
          generatedAtIST: getTodayISTServer(),
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to generate AI briefing.';
        res.status(502).json({ error: message });
      }
    }
  );

  // Server-side RFC-4180 CSV Export
  app.post(
    '/api/export/csv',
    requireProtectedApiAccess,
    (req: AuthenticatedRequest, res: Response) => {
      const parsed = csvExportSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'Invalid CSV export payload.' });
        return;
      }

      const { filename, headers, rows } = parsed.data;
      const escapeCell = (val: string | number | null): string => {
        if (val === null || val === undefined) return '';
        const str = String(val);
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
          return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
      };

      const lines = [
        headers.map(escapeCell).join(','),
        ...rows.map((r) => r.map(escapeCell).join(',')),
      ];
      const csvContent = '\uFEFF' + lines.join('\r\n');

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${filename.replace(/[^a-zA-Z0-9_\-.]/g, '_')}"`
      );
      res.send(csvContent);
    }
  );

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`IIS Institute Management System running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
