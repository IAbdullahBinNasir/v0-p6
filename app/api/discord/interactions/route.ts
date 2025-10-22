// app/api/discord/interactions/route.ts
import { config } from "@/configs/config"
import { NextResponse, type NextRequest } from "next/server"
import nacl from "tweetnacl"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"
export const maxDuration = 10

const InteractionType = {
  PING: 1,
  APPLICATION_COMMAND: 2,
  MESSAGE_COMPONENT: 3,
  APPLICATION_COMMAND_AUTOCOMPLETE: 4,
  MODAL_SUBMIT: 5,
} as const

const InteractionCallbackType = {
  PONG: 1,
  CHANNEL_MESSAGE_WITH_SOURCE: 4,
  DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE: 5,
  DEFERRED_UPDATE_MESSAGE: 6,
  UPDATE_MESSAGE: 7,
  MODAL: 9,
} as const

const EPHEMERAL = 1 << 6

function verifySignature(req: NextRequest, rawBody: string) {
  const sig = req.headers.get("x-signature-ed25519") || ""
  const ts = req.headers.get("x-signature-timestamp") || ""
  if (!sig || !ts || !config.discordPublicKey) return false
  return nacl.sign.detached.verify(
    Buffer.from(ts + rawBody),
    Buffer.from(sig, "hex"),
    Buffer.from(config.discordPublicKey, "hex"),
  )
}

function getBaseUrl(req: NextRequest) {
  try {
    if (config.backendUrl && /^https?:\/\//i.test(config.backendUrl)) return config.backendUrl.replace(/\/+$/, "")
  } catch {}
  const u = new URL(req.url)
  return `${u.protocol}//${u.host}`
}

type AssignedProject = { id: number; name: string }

async function fetchJsonTrace(label: string, url: string, init?: RequestInit) {
  const headers = Object.fromEntries(Object.entries(init?.headers || {}).map(([k, v]) => [k, String(v)]))
  const bodyLen = init?.body ? JSON.stringify(init.body).length : 0
  console.log(`[interactions][${label}] → ${init?.method || "GET"} ${url} headers=${JSON.stringify(headers)} bodyLen=${bodyLen}`)
  const t0 = Date.now()
  const res = await fetch(url, init)
  const ms = Date.now() - t0
  console.log(`[interactions][${label}] ← ${res.status} ${res.statusText} (${ms}ms)`)
  return res
}

async function getAssignedProjects(discordId: string, base: string): Promise<AssignedProject[]> {
  const url = `${base}/api/discord/assigned-projects?discord_id=${encodeURIComponent(discordId)}`
  const res = await fetchJsonTrace("assigned-projects", url, { headers: { "Content-Type": "application/json" }, cache: "no-store" })
  if (!res.ok) throw new Error(`Failed to load assigned projects (${res.status})`)
  return (await res.json()) as AssignedProject[]
}

async function postJson(base: string, path: string, body: unknown, headers: Record<string, string> = {}) {
  const url = `${base}${path}`
  const res = await fetchJsonTrace("post-json", url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`
    try {
      const j = await res.json()
      msg = j?.error || j?.message || msg
    } catch {
      try { msg = await res.text() } catch {}
    }
    throw new Error(msg)
  }
  try { return await res.json() } catch { return null }
}

async function patchJson(base: string, path: string, body: unknown, headers: Record<string, string> = {}) {
  const url = `${base}${path}`
  const res = await fetchJsonTrace("patch-json", url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`
    try {
      const j = await res.json()
      msg = j?.error || j?.message || msg
    } catch {
      try { msg = await res.text() } catch {}
    }
    throw new Error(msg)
  }
  try { return await res.json() } catch { return null }
}

async function sendFollowup(applicationId: string | undefined, token: string | undefined, content: string, ephemeral = false) {
  const appId = applicationId || config.discordAppId
  if (!appId || !token) return
  const url = `https://discord.com/api/v10/webhooks/${appId}/${token}`
  const res = await fetchJsonTrace("followup", url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content, flags: ephemeral ? EPHEMERAL : undefined }),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    console.error(`[interactions][followup] failed: ${res.status} ${res.statusText}: ${text}`)
    throw new Error(`Fetch failed (followup) ${res.status} ${res.statusText}: ${text}`)
  }
}

async function editOriginal(applicationId: string | undefined, token: string | undefined, data: Record<string, any>) {
  const appId = applicationId || config.discordAppId
  if (!appId || !token) return
  const url = `https://discord.com/api/v10/webhooks/${appId}/${token}/messages/@original`
  await fetchJsonTrace("edit-original", url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).catch(() => {})
}

function optionValue(id: number, name: string) {
  return `${id}::${encodeURIComponent(name)}`
}
function parseOptionValue(v: string | undefined): { id: string | null; name: string } {
  if (!v) return { id: null, name: "Project" }
  const [id, enc] = v.split("::")
  return { id: id || null, name: enc ? decodeURIComponent(enc) : "Project" }
}

function buildProjectSelect(customId: string, projects: AssignedProject[], placeholder: string) {
  return {
    type: 1,
    components: [
      {
        type: 3,
        custom_id: customId,
        placeholder,
        options: projects.slice(0, 25).map((p) => ({ label: p.name, value: optionValue(p.id, p.name) })),
      },
    ],
  }
}

function buildStatusSelect(customId: string) {
  return {
    type: 1,
    components: [
      {
        type: 3,
        custom_id: customId,
        placeholder: "Pick a status",
        options: [{ label: "completed", value: "completed" }],
      },
    ],
  }
}

function buildProgressModal(projectId: string, projectName: string) {
  return {
    title: "Post a recent update",
    custom_id: `progress_modal:${projectId}:${encodeURIComponent(projectName)}`,
    components: [
      { type: 1, components: [{ type: 4, custom_id: "title_input", label: "Title", style: 1, min_length: 3, max_length: 120, required: true }] },
      { type: 1, components: [{ type: 4, custom_id: "desc_input", label: "Description (optional)", style: 2, required: false, max_length: 2000 }] },
    ],
  }
}

export async function POST(req: NextRequest) {
  const raw = await req.text()
  if (!verifySignature(req, raw)) return new NextResponse("Bad signature", { status: 401 })

  const body = JSON.parse(raw)
  const base = getBaseUrl(req)
  const envProbe = {
    hasBackendUrl: !!config.backendUrl,
    hasServiceBotToken: !!config.serviceBotToken,
    hasAppId: !!config.discordAppId,
    hasPublicKey: !!config.discordPublicKey,
  }
  console.log("[interactions] base:", base, "env:", envProbe)

  if (body?.type === InteractionType.PING) {
    return NextResponse.json({ type: InteractionCallbackType.PONG })
  }

  const userId: string = body?.member?.user?.id || body?.user?.id || ""
  const token: string | undefined = body?.token
  const applicationId: string | undefined = body?.application_id

  // APPLICATION COMMANDS
  if (body?.type === InteractionType.APPLICATION_COMMAND) {
    const name = body?.data?.name as string | undefined

    if (name === "progress-update") {
      try {
        const projects = await getAssignedProjects(userId, base)
        if (!projects.length) {
          return NextResponse.json({
            type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
            data: { content: "No projects are assigned to you yet.", flags: EPHEMERAL },
          })
        }
        return NextResponse.json({
          type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
          data: {
            content: "Choose the project you want to post a recent update for:",
            flags: EPHEMERAL,
            components: [buildProjectSelect("pick_project_for_progress", projects, "Select a project")],
          },
        })
      } catch (err: any) {
        return NextResponse.json({
          type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
          data: { content: `❌ Error: ${err?.message || "failed to load projects"}`, flags: EPHEMERAL },
        })
      }
    }

    if (name === "milestone-status") {
      try {
        const projects = await getAssignedProjects(userId, base)
        if (!projects.length) {
          return NextResponse.json({
            type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
            data: { content: "No projects are assigned to you yet.", flags: EPHEMERAL },
          })
        }
        return NextResponse.json({
          type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
          data: {
            content: "Choose the project whose active milestone you want to update:",
            flags: EPHEMERAL,
            components: [buildProjectSelect("pick_project_for_milestone", projects, "Select a project")],
          },
        })
      } catch (err: any) {
        return NextResponse.json({
          type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
          data: { content: `❌ Error: ${err?.message || "failed to load projects"}`, flags: EPHEMERAL },
        })
      }
    }

    return NextResponse.json({
      type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
      data: { content: "Unknown command.", flags: EPHEMERAL },
    })
  }

  // MESSAGE COMPONENTS
  if (body?.type === InteractionType.MESSAGE_COMPONENT) {
    const customId = body?.data?.custom_id as string
    const values: string[] = body?.data?.values || []
    const picked = parseOptionValue(values[0])

    if (customId === "pick_project_for_progress") {
      if (!picked.id) {
        return NextResponse.json({
          type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
          data: { content: "❌ No project selected.", flags: EPHEMERAL },
        })
      }
      return NextResponse.json({ type: InteractionCallbackType.MODAL, data: buildProgressModal(picked.id, picked.name) })
    }

    if (customId === "pick_project_for_milestone") {
      if (!picked.id) {
        return NextResponse.json({
          type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
          data: { content: "❌ No project selected.", flags: EPHEMERAL },
        })
      }
      const statusCustomId = `set_status:${picked.id}:${encodeURIComponent(picked.name)}`
      return NextResponse.json({
        type: InteractionCallbackType.UPDATE_MESSAGE,
        data: {
          content:
            "Pick a status to apply to the **active milestone**.\n" +
            "_Note: you can only actually **apply** `completed`. Choosing anything else will just inform you._",
          components: [buildStatusSelect(statusCustomId)],
          flags: EPHEMERAL,
        },
      })
    }

    if (customId.startsWith("set_status:")) {
      const parts = customId.split(":")
      const projectId = parts[1]
      const projectName = decodeURIComponent(parts[2] || "Project")
      const choice = (body?.data?.values?.[0] as string) || ""

      // ACK immediately (so Discord doesn't time out)
      const ack = NextResponse.json({ type: InteractionCallbackType.DEFERRED_UPDATE_MESSAGE })

      // Do work asynchronously AFTER responding
      queueMicrotask(async () => {
        try {
          if (choice !== "completed") {
            await editOriginal(applicationId, token, {
              content:
                `You picked \`${choice}\`. Via Discord you can only mark the active milestone as \`completed\`. ` +
                `No changes were made.`,
              components: [],
              flags: EPHEMERAL,
            })
            return
          }

          if (!config.serviceBotToken) throw new Error("Server misconfigured: SERVICE_BOT_TOKEN")
          await patchJson(base, `/api/projects/${projectId}/milestones`, { status: "completed", callerDiscordId: userId }, { Authorization: `Bearer ${config.serviceBotToken}` })

          await sendFollowup(applicationId, token, `🎯 **${projectName}** — active milestone **marked completed** by <@${userId}>`, false)
          await editOriginal(applicationId, token, { content: `Done. Active milestone marked **completed** for **${projectName}**.`, components: [], flags: EPHEMERAL })
        } catch (err: any) {
          console.error("[interactions][set_status] error:", err?.message || err)
          const msg = `❌ ${err?.message || "Failed to update milestone"}`
          try {
            await editOriginal(applicationId, token, { content: msg, components: [], flags: EPHEMERAL })
          } catch { /* noop */ }
        }
      })

      return ack
    }

    return NextResponse.json({
      type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
      data: { content: "Unknown action.", flags: EPHEMERAL },
    })
  }

  // MODAL SUBMIT
  if (body?.type === InteractionType.MODAL_SUBMIT) {
    const customId = body?.data?.custom_id as string
    if (customId.startsWith("progress_modal:")) {
      const parts = customId.split(":")
      const projectId = parts[1]
      const projectName = decodeURIComponent(parts[2] || "Project")

      const fields: Record<string, string> = {}
      for (const row of body.data.components || []) {
        const comp = row?.components?.[0]
        if (comp?.custom_id && typeof comp?.value === "string") fields[comp.custom_id] = comp.value
      }
      const title = fields["title_input"] || ""
      const description = fields["desc_input"] || ""

      // ACK immediately
      const ack = NextResponse.json({ type: InteractionCallbackType.DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE })

      // Do work asynchronously
      queueMicrotask(async () => {
        try {
          if (!config.serviceBotToken) throw new Error("Server misconfigured: SERVICE_BOT_TOKEN")
          await postJson(base, `/api/projects/${projectId}/progress`, { title, description, callerDiscordId: userId }, { Authorization: `Bearer ${config.serviceBotToken}` })

          await sendFollowup(
            applicationId,
            token,
            [
              `📝 **${projectName}** — recent update from <@${userId}>`,
              `**Title:** ${title}`,
              description ? `**Description:** ${description}` : `**Description:** _none_`,
            ].join("\n"),
            false,
          )
          await editOriginal(applicationId, token, { content: "✅ Update posted.", flags: EPHEMERAL })
        } catch (err: any) {
          console.error("[interactions][progress_modal] error:", err?.message || err)
          const msg = `❌ ${err?.message || "Failed to post update"}`
          try {
            await editOriginal(applicationId, token, { content: msg, flags: EPHEMERAL })
          } catch { /* noop */ }
        }
      })

      return ack
    }

    return NextResponse.json({
      type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
      data: { content: "Unknown modal.", flags: EPHEMERAL },
    })
  }

  return NextResponse.json({
    type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
    data: { content: "Unsupported interaction.", flags: EPHEMERAL },
  })
}
