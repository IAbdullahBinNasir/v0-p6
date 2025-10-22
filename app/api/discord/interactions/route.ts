// app/api/discord/interactions/route.ts
import { config } from "@/configs/config"
import { NextResponse, type NextRequest } from "next/server"
import nacl from "tweetnacl"

// Serverless-friendly
export const runtime = "nodejs"
export const dynamic = "force-dynamic"
export const maxDuration = 10

// ---- Discord constants ----
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

// Toggle noisy error echoing to Discord (still ephemeral):
const DEBUG_TO_DISCORD = (process.env.DEBUG_INTERACTIONS || "").toLowerCase() === "true"

// ---- Helpers ----
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
  } catch { }
  const u = new URL(req.url)
  return `${u.protocol}//${u.host}`
}

/**
 * A traced fetch wrapper:
 * - logs URL, method, headers (safe), and body length before request
 * - logs status + response text (up to a limit) on non-OK
 * - throws a rich Error with status + snippet for upper layers
 */
async function fetchWithTrace(
  label: string,
  url: string,
  init: RequestInit = {},
  { echoBody = false }: { echoBody?: boolean } = {},
) {
  const startedAt = Date.now()
  const method = (init.method || "GET").toUpperCase()
  const headers = Object.fromEntries(Object.entries((init.headers || {}) as Record<string, string>).map(([k, v]) => {
    if (/authorization/i.test(k)) return [k, "****"]
    return [k, v]
  }))
  let bodyLen = 0
  try {
    if (init.body && typeof init.body === "string") bodyLen = init.body.length
  } catch { }

  console.log(`[interactions][${label}] → ${method} ${url} headers=${JSON.stringify(headers)} bodyLen=${bodyLen}`)

  const res = await fetch(url, init)

  const dur = Date.now() - startedAt
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    const snippet = text.slice(0, 500) // cap logs
    console.error(
      `[interactions][${label}] ← ${res.status} ${res.statusText} (${dur}ms)\n` +
      `URL: ${url}\n` +
      `Response: ${snippet || "<no body>"}`
    )
    const err = new Error(`Fetch failed (${label}) ${res.status} ${res.statusText}: ${snippet || "<no body>"}`)
      ; (err as any).status = res.status
      ; (err as any).url = url
    throw err
  }

  // Try to parse JSON, otherwise return text/null
  const ct = res.headers.get("content-type") || ""
  let data: any = null
  if (ct.includes("application/json")) {
    data = await res.json().catch(() => null)
  } else {
    data = await res.text().catch(() => null)
  }

  console.log(`[interactions][${label}] ← ${res.status} OK (${dur}ms)`)
  if (echoBody && data) {
    console.log(`[interactions][${label}] body:`, typeof data === "string" ? data.slice(0, 500) : data)
  }

  return data
}

async function sendFollowup(applicationId: string | undefined, token: string | undefined, content: string, ephemeral = false) {
  const appId = applicationId || config.discordAppId
  if (!appId || !token) {
    console.warn("[interactions][followup] missing appId or token; skipping")
    return
  }
  const url = `https://discord.com/api/v10/webhooks/${appId}/${token}`
  try {
    await fetchWithTrace(
      "followup",
      url,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content, flags: ephemeral ? EPHEMERAL : undefined }),
      },
    )
  } catch (err: any) {
    console.error("[interactions][followup] failed:", err?.message || err)
  }
}

type AssignedProject = { id: number; name: string }
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
      {
        type: 1,
        components: [
          {
            type: 4,
            custom_id: "title_input",
            label: "Title",
            style: 1,
            min_length: 3,
            max_length: 120,
            required: true,
          },
        ],
      },
      {
        type: 1,
        components: [
          {
            type: 4,
            custom_id: "desc_input",
            label: "Description (optional)",
            style: 2,
            required: false,
            max_length: 2000,
          },
        ],
      },
    ],
  }
}

async function getAssignedProjects(discordId: string, base: string): Promise<AssignedProject[]> {
  const url = `${base}/api/discord/assigned-projects?discord_id=${encodeURIComponent(discordId)}`
  const data = await fetchWithTrace("assigned-projects", url, {
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
  })
  return Array.isArray(data) ? data as AssignedProject[] : []
}

async function completeActiveMilestone(base: string, projectId: string | undefined, userId: string) {
  if (!config.serviceBotToken) throw new Error("Server misconfigured: SERVICE_BOT_TOKEN")
  const url = `${base}/api/projects/${projectId}/milestones`
  return fetchWithTrace("patch-milestone", url, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.serviceBotToken}`,
    },
    body: JSON.stringify({ status: "completed", callerDiscordId: userId }),
  })
}

async function postProgress(base: string, projectId: string | undefined, title: string, description: string, userId: string) {
  if (!config.serviceBotToken) throw new Error("Server misconfigured: SERVICE_BOT_TOKEN")
  const url = `${base}/api/projects/${projectId}/progress`
  return fetchWithTrace("post-progress", url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.serviceBotToken}`,
    },
    body: JSON.stringify({ title, description, callerDiscordId: userId }),
  })
}

// ---- ROUTE ----
export async function POST(req: NextRequest) {
  const raw = await req.text()
  if (!verifySignature(req, raw)) {
    return new NextResponse("Bad signature", { status: 401 })
  }

  const body = JSON.parse(raw)
  const base = getBaseUrl(req)

  // Log a quick env snapshot (safe)
  console.log("[interactions] base:", base, "env:", {
    hasBackendUrl: !!config.backendUrl,
    hasServiceBotToken: !!config.serviceBotToken,
    hasAppId: !!config.discordAppId,
    hasPublicKey: !!config.discordPublicKey,
  })

  // 1) PING
  if (body?.type === InteractionType.PING) {
    return NextResponse.json({ type: InteractionCallbackType.PONG })
  }

  const userId: string = body?.member?.user?.id || body?.user?.id || ""
  const interactionToken: string | undefined = body?.token
  const applicationId: string | undefined = body?.application_id

  // 2) APPLICATION COMMANDS
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
        console.error("[interactions][progress-update] error:", err?.message || err)
        const msg = DEBUG_TO_DISCORD ? `❌ Error: ${err?.message || "failed to load projects"}` : "❌ Error loading projects"
        return NextResponse.json({
          type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
          data: { content: msg, flags: EPHEMERAL },
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
        console.error("[interactions][milestone-status] error:", err?.message || err)
        const msg = DEBUG_TO_DISCORD ? `❌ Error: ${err?.message || "failed to load projects"}` : "❌ Error loading projects"
        return NextResponse.json({
          type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
          data: { content: msg, flags: EPHEMERAL },
        })
      }
    }

    return NextResponse.json({
      type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
      data: { content: "Unknown command.", flags: EPHEMERAL },
    })
  }

  // 3) MESSAGE COMPONENTS
  if (body?.type === InteractionType.MESSAGE_COMPONENT) {
    const customId = body?.data?.custom_id as string
    const values: string[] = body?.data?.values || []
    const picked = parseOptionValue(values[0])

    // Project picked → progress modal
    if (customId === "pick_project_for_progress") {
      if (!picked.id) {
        return NextResponse.json({
          type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
          data: { content: "❌ No project selected.", flags: EPHEMERAL },
        })
      }
      return NextResponse.json({
        type: InteractionCallbackType.MODAL,
        data: buildProgressModal(picked.id, picked.name),
      })
    }

    // Project picked → milestone status select
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

    // Status chosen
    if (customId.startsWith("set_status:")) {
      const parts = customId.split(":")
      const projectId = parts[1]
      const projectName = decodeURIComponent(parts[2] || "Project")
      const choice = (body?.data?.values?.[0] as string) || ""

      if (choice !== "completed") {
        return NextResponse.json({
          type: InteractionCallbackType.UPDATE_MESSAGE,
          data: {
            content:
              `You picked \`${choice}\`. Via Discord you can only mark the active milestone as \`completed\`. ` +
              `No changes were made.`,
            components: [],
            flags: EPHEMERAL,
          },
        })
      }

      // Do work NOW, then return a deferred update ack
      try {
        await completeActiveMilestone(base, projectId, userId)
        await sendFollowup(
          body?.application_id,
          body?.token,
          `🎯 **${projectName}** — active milestone **marked completed** by <@${userId}>`,
          false
        )
        await sendFollowup(
          body?.application_id,
          body?.token,
          `Done. Active milestone marked **completed** for **${projectName}**.`,
          true
        )
      } catch (err: any) {
        console.error("[interactions][set_status] error:", err?.message || err)
        const msg = DEBUG_TO_DISCORD ? `❌ Error updating milestone: ${err?.message || "unknown error"}` : "❌ Failed to update milestone"
        await sendFollowup(body?.application_id, body?.token, msg, true)
      }

      return NextResponse.json({ type: InteractionCallbackType.DEFERRED_UPDATE_MESSAGE })
    }

    return NextResponse.json({
      type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
      data: { content: "Unknown action.", flags: EPHEMERAL },
    })
  }

  // 4) MODAL SUBMIT (progress update)
  if (body?.type === InteractionType.MODAL_SUBMIT) {
    const customId = body?.data?.custom_id as string
    if (customId.startsWith("progress_modal:")) {
      const parts = customId.split(":")
      const projectId = parts[1]
      const projectName = decodeURIComponent(parts[2] || "Project")

      const fields: Record<string, string> = {}
      for (const row of body.data.components || []) {
        const comp = row?.components?.[0]
        if (comp?.custom_id && typeof comp?.value === "string") {
          fields[comp.custom_id] = comp.value
        }
      }
      const title = fields["title_input"] || ""
      const description = fields["desc_input"] || ""

      try {
        await postProgress(base, projectId, title, description, userId)

        await sendFollowup(
          body?.application_id,
          body?.token,
          [
            `📝 **${projectName}** — recent update from <@${userId}>`,
            `**Title:** ${title}`,
            description ? `**Description:** ${description}` : `**Description:** _none_`,
          ].join("\n"),
          false
        )
        await sendFollowup(body?.application_id, body?.token, `✅ Posted a recent update to **${projectName}**.`, true)
      } catch (err: any) {
        console.error("[interactions][progress_modal] error:", err?.message || err)
        const msg = DEBUG_TO_DISCORD ? `❌ Error: ${err?.message || "failed to post update"}` : "❌ Failed to post update"
        await sendFollowup(body?.application_id, body?.token, msg, true)
      }

      return NextResponse.json({ type: InteractionCallbackType.DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE })
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
