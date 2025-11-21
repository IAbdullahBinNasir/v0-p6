// app/api/github/webhook/route.ts
import { NextRequest, NextResponse } from "next/server"
import { sql } from "@/lib/db"
import crypto from "crypto"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

function normalizeRepo(repo?: string | null): string | null {
    if (!repo) return null
    const r = repo.trim()
    const m = r.match(/^https?:\/\/github\.com\/([^/\s]+)\/([^/\s]+?)(?:\.git|\/)?$/i)
    if (m) return `${m[1]}/${m[2]}`
    if (/^[^/\s]+\/[^/\s]+$/.test(r)) return r
    return null
}

async function findProjectIdByRepo(fullName: string): Promise<number | null> {
    const rows = await sql/*sql*/`
    SELECT id, github_repo
    FROM projects
  `
    for (const row of rows as any[]) {
        const norm = normalizeRepo(row.github_repo)
        if (norm && norm.toLowerCase() === fullName.toLowerCase()) {
            return row.id as number
        }
    }
    return null
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

function verifyGithubSignature(rawBody: string, signatureHeader: string | null): boolean {
    const secret = process.env.GITHUB_WEBHOOK_SECRET
    if (!secret) {
        console.warn("[github webhook] no GITHUB_WEBHOOK_SECRET set, skipping verification")
        return true // or false if you want to enforce it
    }

    if (!signatureHeader || !signatureHeader.startsWith("sha256=")) {
        return false
    }

    const theirSig = signatureHeader.slice("sha256=".length)
    const hmac = crypto.createHmac("sha256", secret)
    hmac.update(rawBody, "utf8")
    const expected = hmac.digest("hex")

    // timing-safe compare
    const aBuf = Buffer.from(theirSig, "hex")
    const bBuf = Buffer.from(expected, "hex")
    if (aBuf.length !== bBuf.length) return false

    // Convert Node Buffer to Uint8Array (ArrayBufferView) using the underlying ArrayBuffer,
    // preserving byteOffset/byteLength to avoid copying and to satisfy TypeScript types.
    const a = new Uint8Array(aBuf.buffer, aBuf.byteOffset, aBuf.byteLength)
    const b = new Uint8Array(bBuf.buffer, bBuf.byteOffset, bBuf.byteLength)
    return crypto.timingSafeEqual(a, b)
}

export async function POST(req: NextRequest) {
    try {
        // 1) read raw body
        const rawBody = await req.text()

        // 2) verify signature
        const sigHeader = req.headers.get("x-hub-signature-256")
        const ok = verifyGithubSignature(rawBody, sigHeader)
        if (!ok) {
            console.warn("[github webhook] invalid signature")
            return NextResponse.json({ ok: false, error: "invalid_signature" }, { status: 401 })
        }

        // 3) parse JSON
        const body = JSON.parse(rawBody)
        const event = req.headers.get("x-github-event")

        const repoFullName: string | undefined = body?.repository?.full_name
        if (!repoFullName) {
            return NextResponse.json({ ok: false, reason: "no_repository" }, { status: 400 })
        }

        const projectId = await findProjectIdByRepo(repoFullName)
        if (!projectId) {
            return NextResponse.json({ ok: true, skipped: "no_matching_project" })
        }

        // --- handle push events (commits) ---
        if (event === "push") {
            const commits = (body.commits || []) as any[]

            for (const commit of commits) {
                await insertActivityLog({
                    projectId,
                    activity_type: "commit",
                    source: "github",
                    title: commit.message?.split("\n")[0] || "Commit",
                    description: commit.message || null,
                    url: commit.url || body?.compare || null,
                    author: commit.author?.name || commit.author?.username || null,
                    timestamp: commit.timestamp || body.head_commit?.timestamp || null,
                })
            }

            return NextResponse.json({ ok: true, handled: "push", commits: commits.length })
        }

        // --- handle pull_request events (merge) ---
        if (event === "pull_request") {
            const action = body.action
            const pr = body.pull_request

            if (action === "closed" && pr?.merged) {
                await insertActivityLog({
                    projectId,
                    activity_type: "merge", // or "pull_request_merged"
                    source: "github",
                    title: pr.title || `Merged PR #${pr.number}`,
                    description: `PR #${pr.number} merged into ${pr.base?.ref || "default branch"}`,
                    url: pr.html_url || null,
                    author: pr.user?.login || null,
                    timestamp: pr.merged_at || pr.updated_at || null,
                })

                return NextResponse.json({ ok: true, handled: "pull_request_merged", pr: pr.number })
            }

            return NextResponse.json({ ok: true, skipped: "pull_request_not_merged" })
        }

        return NextResponse.json({ ok: true, skipped: `unhandled_event:${event}` })
    } catch (e: any) {
        console.error("[github webhook] error:", e)
        return NextResponse.json({ ok: false, error: e?.message || "Server error" }, { status: 500 })
    }
}
