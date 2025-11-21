// app/api/cron/risk-scan/route.ts
import { NextResponse, NextRequest } from "next/server"
import { sql } from "@/lib/db"
import { config } from "@/configs/config"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

// --- helpers ---
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

// ---------- GitHub helpers ----------

type GithubCommitSummary = {
  sha: string
  message: string | null
  authorName: string | null
  date: string | null
  url: string | null
}

type GithubPrSummary = {
  number: number
  title: string | null
  state: string
  merged: boolean
  updatedAt: string | null
  mergedAt: string | null
  url: string | null
}

type GithubCheck = {
  ok: boolean
  reason?: string
  commitActivity?: boolean
  pullActivity?: boolean
  lastCommit?: GithubCommitSummary | null
  lastMergedPr?: GithubPrSummary | null
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
    const sinceDate = new Date(sinceIso)

    // --- latest commit (we want the latest, then check if it's within last 30d) ---
    const commitsUrl = `${base}/commits?per_page=1`
    const cRes = await fetch(commitsUrl, { headers, cache: "no-store" })
    if (!cRes.ok) {
      const t = await cRes.text().catch(() => "")
      return { ok: false, reason: `commits_check_failed:${cRes.status}:${t}` }
    }
    const commits = (await cRes.json()) as any[]
    let lastCommit: GithubCommitSummary | null = null
    let commitActivity = false

    if (Array.isArray(commits) && commits.length > 0) {
      const c = commits[0]
      const cMsg = c?.commit?.message ?? null
      const cDate: string | null =
        c?.commit?.author?.date ?? c?.commit?.committer?.date ?? null
      const cAuthor: string | null =
        c?.commit?.author?.name ??
        c?.author?.login ??
        c?.commit?.committer?.name ??
        null

      lastCommit = {
        sha: c?.sha ?? "",
        message: cMsg,
        authorName: cAuthor,
        date: cDate,
        url: c?.html_url ?? null,
      }

      if (cDate) {
        const d = new Date(cDate)
        commitActivity = d >= sinceDate
      }
    }

    // --- latest merged PR (pick most recently merged; check if within 30d) ---
    const prsUrl = `${base}/pulls?state=all&sort=updated&direction=desc&per_page=20`
    const pRes = await fetch(prsUrl, { headers, cache: "no-store" })
    if (!pRes.ok) {
      const t = await pRes.text().catch(() => "")
      return {
        ok: false,
        reason: `prs_check_failed:${pRes.status}:${t}`,
        commitActivity,
        lastCommit,
      }
    }
    const pulls = (await pRes.json()) as any[]
    let lastMergedPr: GithubPrSummary | null = null
    let pullActivity = false

    if (Array.isArray(pulls) && pulls.length > 0) {
      const mergedPr = pulls.find((pr) => !!pr?.merged_at) ?? null
      if (mergedPr) {
        const mergedAt: string | null = mergedPr.merged_at ?? null
        const updatedAt: string | null = mergedPr.updated_at ?? null

        lastMergedPr = {
          number: mergedPr.number,
          title: mergedPr.title ?? null,
          state: mergedPr.state ?? "closed",
          merged: !!mergedPr.merged_at,
          updatedAt,
          mergedAt,
          url: mergedPr.html_url ?? null,
        }

        const compareDateStr = mergedAt ?? updatedAt
        if (compareDateStr) {
          const d = new Date(compareDateStr)
          pullActivity = d >= sinceDate
        }
      }
    }

    return {
      ok: true,
      commitActivity,
      pullActivity,
      lastCommit,
      lastMergedPr,
    }
  } catch (e: any) {
    return { ok: false, reason: `github_error:${e?.message || "unknown"}` }
  }
}

// ---------- activity_logs helpers ----------

async function activityExists(projectId: number, activity_type: string, url: string | null): Promise<boolean> {
  if (!url) return false
  const rows = await sql/*sql*/`
    SELECT 1
    FROM activity_logs
    WHERE project_id = ${projectId}
      AND activity_type = ${activity_type}
      AND url = ${url}
    LIMIT 1
  `
  return rows.length > 0
}

async function insertActivityLog(entry: {
  projectId: number
  activity_type: string
  source: string
  title: string | null
  description: string | null
  url: string | null
  author: string | null
  timestamp: string | null
}) {
  const { projectId, activity_type, source, title, description, url, author, timestamp } = entry

  await sql/*sql*/`
    INSERT INTO activity_logs (project_id, activity_type, source, title, description, url, author, "timestamp")
    VALUES (
      ${projectId},
      ${activity_type},
      ${source},
      ${title},
      ${description},
      ${url},
      ${author},
      ${timestamp ? new Date(timestamp) : new Date()}
    )
  `
}

// --- core job ---
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

  for (const p of projects as any[]) {
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
        gh = {
          commitActivity: !!ghRes.commitActivity,
          pullActivity: !!ghRes.pullActivity,
        }

        // ---- GitHub → Recent Updates (activity_logs) ----
        // Latest commit → activity_type = "commit", source = "github"
        if (ghRes.lastCommit && ghRes.lastCommit.url) {
          const already = await activityExists(p.id, "commit", ghRes.lastCommit.url)
          if (!already) {
            await insertActivityLog({
              projectId: p.id,
              activity_type: "commit",
              source: "github", // this becomes the "GITHUB" tag in your UI
              title: ghRes.lastCommit.message?.split("\n")[0] || "Commit",
              description: ghRes.lastCommit.message,
              url: ghRes.lastCommit.url,
              author: ghRes.lastCommit.authorName,
              timestamp: ghRes.lastCommit.date,
            })
          }
        }

        // Latest merged PR → activity_type = "merge", source = "github"
        if (ghRes.lastMergedPr && ghRes.lastMergedPr.url) {
          const already = await activityExists(p.id, "merge", ghRes.lastMergedPr.url)
          if (!already) {
            await insertActivityLog({
              projectId: p.id,
              activity_type: "merge",
              source: "github", // will show as GITHUB tag
              title: ghRes.lastMergedPr.title || `Merged PR #${ghRes.lastMergedPr.number}`,
              description: ghRes.lastMergedPr.merged
                ? `PR #${ghRes.lastMergedPr.number} merged`
                : `PR #${ghRes.lastMergedPr.number} (${ghRes.lastMergedPr.state})`,
              url: ghRes.lastMergedPr.url,
              author: null,
              timestamp: ghRes.lastMergedPr.mergedAt || ghRes.lastMergedPr.updatedAt,
            })
          }
        }
        // ---- end GitHub → Recent Updates ----
      }
    } else {
      repo_check = "none"
    }

    // too new → still appear in results but not marked at_risk
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

// --- POST: manual / scheduler trigger with SERVICE_BOT_TOKEN ---
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
