// app/api/cron/risk-scan/route.ts
import { NextResponse, NextRequest } from "next/server"
import { sql } from "@/lib/db"
import { config } from "@/configs/config"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// --- your helpers (unchanged) ---
const DAYS_30_MS = 30 * 24 * 60 * 60 * 1000
function isAtLeast30DaysOld(createdAt: string | Date) {
  const created = new Date(createdAt)
  const age = Date.now() - created.getTime()
  return age >= DAYS_30_MS
}
function normalizeRepo(repo?: string | null): string | null {
  if (!repo) return null
  const r = repo.trim()
  const m = r.match(/^https?:\/\/github\.com\/([^/\s]+)\/([^/\s]+?)(?:\.git|\/)?$/i)
  if (m) return `${m[1]}/${m[2]}`
  if (/^[^/\s]+\/[^/\s]+$/.test(r)) return r
  return null
}
async function getDiscordActivityCount(projectId: number, sinceIso: string) {
  const rows = await sql/*sql*/`
    SELECT COUNT(*)::int AS cnt
    FROM activity_logs
    WHERE project_id = ${projectId}
      AND source = 'discord'
      AND "timestamp" >= ${sinceIso}
  `
  return (rows?.[0]?.cnt ?? 0) as number
}
type GithubCheck = {
  ok: boolean
  reason?: string
  commitActivity?: boolean
  pullActivity?: boolean
}
async function checkGithubActivity(repo: string, sinceIso: string): Promise<GithubCheck> {
  if (!repo || !repo.includes("/")) return { ok: false, reason: "invalid_repo_format" }
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "risk-scan",
  }
  if (config.githubToken) headers.Authorization = `Bearer ${config.githubToken}`
  const base = `https://api.github.com/repos/${repo}`
  try {
    const commitsUrl = `${base}/commits?since=${encodeURIComponent(sinceIso)}&per_page=1`
    const cRes = await fetch(commitsUrl, { headers, cache: "no-store" })
    if (!cRes.ok) {
      const t = await cRes.text().catch(() => "")
      return { ok: false, reason: `commits_check_failed:${cRes.status}:${t}` }
    }
    const commits = (await cRes.json()) as any[]
    const commitActivity = Array.isArray(commits) && commits.length > 0

    const prsUrl = `${base}/pulls?state=all&sort=updated&direction=desc&per_page=5`
    const pRes = await fetch(prsUrl, { headers, cache: "no-store" })
    if (!pRes.ok) {
      const t = await pRes.text().catch(() => "")
      return { ok: false, reason: `prs_check_failed:${pRes.status}:${t}`, commitActivity }
    }
    const pulls = (await pRes.json()) as any[]
    const sinceTs = new Date(sinceIso).getTime()
    const pullActivity = (Array.isArray(pulls) ? pulls : []).some((pr) => {
      const updatedAt = pr?.updated_at ? new Date(pr.updated_at).getTime() : 0
      const mergedAt = pr?.merged_at ? new Date(pr.merged_at).getTime() : 0
      return updatedAt >= sinceTs || mergedAt >= sinceTs
    })
    return { ok: true, commitActivity, pullActivity }
  } catch (e: any) {
    return { ok: false, reason: `github_error:${e?.message || "unknown"}` }
  }
}

// --- core job (your existing POST logic moved into a function) ---
async function runRiskScanJob() {
  const since = new Date(Date.now() - DAYS_30_MS)
  const sinceIso = since.toISOString()

  const projects = await sql/*sql*/`
    SELECT id, name, status, github_repo, created_at
    FROM projects
    ORDER BY created_at DESC
  `

  const results: Array<{
    projectId: number
    name: string
    created_at: string
    age_days: number
    repo: string | null
    repo_check: "none" | "checked" | "invalid" | "error"
    github: { commitActivity?: boolean; pullActivity?: boolean; reason?: string }
    discord: { hasActivity: boolean; countKnown?: number }
    final: "active" | "at_risk" | "too_new"
    note: string
  }> = []

  for (const p of projects) {
    const createdAt = new Date(p.created_at)
    const ageDays = Math.floor((Date.now() - createdAt.getTime()) / (24 * 60 * 60 * 1000))

    const discordCount = await getDiscordActivityCount(p.id, sinceIso)
    const discordHas = discordCount > 0

    const normRepo = normalizeRepo(p.github_repo)
    let repo_check: "none" | "checked" | "invalid" | "error" = "none"
    let gh: { commitActivity?: boolean; pullActivity?: boolean; reason?: string } = {}

    if (normRepo === null && p.github_repo) {
      repo_check = "invalid"
      gh = { reason: "invalid_repo_format" }
    } else if (normRepo) {
      const ghRes = await checkGithubActivity(normRepo, sinceIso)
      if (!ghRes.ok) {
        repo_check = ghRes.reason?.startsWith("invalid_repo_format") ? "invalid" : "error"
        gh = { reason: ghRes.reason }
      } else {
        repo_check = "checked"
        gh = { commitActivity: !!ghRes.commitActivity, pullActivity: !!ghRes.pullActivity }
      }
    } else {
      repo_check = "none"
    }

    if (!isAtLeast30DaysOld(createdAt)) {
      results.push({
        projectId: p.id,
        name: p.name,
        created_at: createdAt.toISOString(),
        age_days: ageDays,
        repo: normRepo,
        repo_check,
        github: gh,
        discord: { hasActivity: discordHas, countKnown: discordCount },
        final: "too_new",
        note: "Project age < 30 days",
      })
      continue
    }

    const noGithubActivity =
      !normRepo ||
      (repo_check === "checked" && !gh.commitActivity && !gh.pullActivity) ||
      repo_check === "invalid" ||
      repo_check === "error"

    const final: "active" | "at_risk" = !discordHas && noGithubActivity ? "at_risk" : "active"

    let note = ""
    if (final === "at_risk") {
      if (!normRepo) note = "No Discord updates in 30d and no GitHub repo set"
      else if (repo_check === "invalid") note = "No Discord updates in 30d and GitHub repo format is invalid"
      else if (repo_check === "error") note = "No Discord updates in 30d and GitHub check errored"
      else note = "No Discord updates in 30d and no GitHub activity in 30d"
    } else {
      note = "Has Discord and/or GitHub activity in 30d"
    }

    results.push({
      projectId: p.id,
      name: p.name,
      created_at: createdAt.toISOString(),
      age_days: ageDays,
      repo: normRepo,
      repo_check,
      github: gh,
      discord: { hasActivity: discordHas, countKnown: discordCount },
      final,
      note,
    })
  }

  return { since: sinceIso, results }
}

// --- POST: for manual/scripted trigger with SERVICE_BOT_TOKEN ---
export async function POST(req: Request) {
  try {
    const auth = req.headers.get("authorization") || ""
    const token = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : ""
    if (!config.serviceBotToken || token !== config.serviceBotToken) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    const out = await runRiskScanJob()
    return NextResponse.json(out)
  } catch (e: any) {
    if (process.env.NODE_ENV === "development") {
      console.error("[risk-scan][POST] error:", e)
    }
    return NextResponse.json({ error: e?.message || "Server error" }, { status: 500 })
  }
}

// --- GET: for Vercel Scheduled Functions (no headers supported) ---
export async function GET(req: NextRequest) {
  try {
    // Optional extra safety: only allow from Vercel cron in prod
    const isCron = req.headers.get("x-vercel-cron") === "1"
    if (process.env.VERCEL && !isCron) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 })
    }

    const out = await runRiskScanJob()
    return NextResponse.json(out)
  } catch (e: any) {
    if (process.env.NODE_ENV === "development") {
      console.error("[risk-scan][GET] error:", e)
    }
    return NextResponse.json({ error: e?.message || "Server error" }, { status: 500 })
  }
}
