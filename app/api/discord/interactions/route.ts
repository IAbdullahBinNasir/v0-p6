// app/api/discord/interactions/route.ts
import { config } from "@/configs/config"
import { NextResponse, type NextRequest } from "next/server"
import nacl from "tweetnacl"

// Vercel/Next serverless friendly
export const runtime = "nodejs"
export const dynamic = "force-dynamic"

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

// Ephemeral flag bit for responses
const EPHEMERAL = 1 << 6

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

type AssignedProject = { id: number; name: string }

/** Call your backend for projects assigned to this Discord user */
async function getAssignedProjects(discordId: string): Promise<AssignedProject[]> {
  if (!config.backendUrl) throw new Error("env for backend url not set")
  const url = `${config.backendUrl}/api/discord/assigned-projects?discord_id=${encodeURIComponent(discordId)}`
  const res = await fetch(url, { headers: { "Content-Type": "application/json" }, cache: "no-store" })
  if (!res.ok) throw new Error(`Failed to load assigned projects (${res.status})`)
  return (await res.json()) as AssignedProject[]
}

/** Backend calls mirroring your commander helpers */
async function postJson(url: string, body: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(url, {
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
      try {
        msg = await res.text()
      } catch {}
    }
    throw new Error(msg)
  }
  try {
    return await res.json()
  } catch {
    return null
  }
}

async function patchJson(url: string, body: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(url, {
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
      try {
        msg = await res.text()
      } catch {}
    }
    throw new Error(msg)
  }
  try {
    return await res.json()
  } catch {
    return null
  }
}

/** Send a follow-up message via the interaction webhook (can be public if you omit EPHEMERAL) */
async function sendFollowup(token: string, content: string, ephemeral = false) {
  if (!config.discordAppId) throw new Error("env for DISCORD APPLICATION ID not set")
  const url = `https://discord.com/api/v10/webhooks/${config.discordAppId}/${token}`
  await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      content,
      flags: ephemeral ? EPHEMERAL : undefined,
    }),
  })
}

/** Utilities to build Discord component payloads */
function optionValue(id: number, name: string) {
  // encode label into value so we can read it on the server later
  return `${id}::${encodeURIComponent(name)}`
}
function parseOptionValue(v: string | undefined): { id: string | null; name: string } {
  if (!v) return { id: null, name: "Project" }
  const [id, enc] = v.split("::")
  return { id: id || null, name: enc ? decodeURIComponent(enc) : "Project" }
}

// Build a SELECT of projects (max 25) — ephemeral
function buildProjectSelect(customId: string, projects: AssignedProject[], placeholder: string) {
  return {
    type: 1, // ActionRow
    components: [
      {
        type: 3, // StringSelect
        custom_id: customId,
        placeholder,
        options: projects.slice(0, 25).map((p) => ({
          label: p.name,
          value: optionValue(p.id, p.name),
        })),
      },
    ],
  }
}

// Build the single-option status select for "completed"
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

// Build the modal for progress update
function buildProgressModal(projectId: string, projectName: string) {
  return {
    title: "Post a recent update",
    custom_id: `progress_modal:${projectId}:${encodeURIComponent(projectName)}`,
    components: [
      {
        type: 1,
        components: [
          {
            type: 4, // Text input
            custom_id: "title_input",
            label: "Title",
            style: 1, // Short
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
            style: 2, // Paragraph
            required: false,
            max_length: 2000,
          },
        ],
      },
    ],
  }
}

// ---- ROUTE ----
export async function POST(req: NextRequest) {
  const raw = await req.text()
  if (!verifySignature(req, raw)) {
    return new NextResponse("Bad signature", { status: 401 })
  }

  const body = JSON.parse(raw)

  // 1) PING
  if (body?.type === InteractionType.PING) {
    return NextResponse.json({ type: InteractionCallbackType.PONG })
  }

  const userId: string =
    body?.member?.user?.id || body?.user?.id || "" // handles guild + DMs

  // 2) APPLICATION COMMANDS
  if (body?.type === InteractionType.APPLICATION_COMMAND) {
    const name = body?.data?.name as string | undefined

    if (name === "progress-update") {
      try {
        const projects = await getAssignedProjects(userId)
        if (!projects.length) {
          return NextResponse.json({
            type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
            data: {
              content: "No projects are assigned to you yet.",
              flags: EPHEMERAL,
            },
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
        const projects = await getAssignedProjects(userId)
        if (!projects.length) {
          return NextResponse.json({
            type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
            data: {
              content: "No projects are assigned to you yet.",
              flags: EPHEMERAL,
            },
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

  // 3) MESSAGE COMPONENTS (selects)
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
      // Return a modal
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

      // If not "completed", just inform
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

      // Acknowledge immediately (defer update), then do the PATCH and follow-up
      queueMicrotask(async () => {
        try {
          if (!config.serviceBotToken || !config.backendUrl) throw new Error("Server misconfigured")
          await patchJson(
            `${config.backendUrl}/api/projects/${projectId}/milestones`,
            { status: "completed", callerDiscordId: userId },
            { Authorization: `Bearer ${config.serviceBotToken}` },
          )
          // Public confirmation in the channel:
          await sendFollowup(
            body.token,
            `🎯 **${projectName}** — active milestone **marked completed** by <@${userId}>`,
            false,
          )
          // Ephemeral ack to user
          await sendFollowup(body.token, `Done. Active milestone marked **completed** for **${projectName}**.`, true)
        } catch (err: any) {
          await sendFollowup(body.token, `❌ Error updating milestone: ${err?.message || "unknown error"}`, true)
        }
      })

      return NextResponse.json({ type: InteractionCallbackType.DEFERRED_UPDATE_MESSAGE })
    }

    // Unknown component
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

      // Extract fields from modal
      // body.data.components is ActionRow[] -> each row has components[0] with { custom_id, value }
      const fields: Record<string, string> = {}
      for (const row of body.data.components || []) {
        const comp = row?.components?.[0]
        if (comp?.custom_id && typeof comp?.value === "string") {
          fields[comp.custom_id] = comp.value
        }
      }
      const title = fields["title_input"] || ""
      const description = fields["desc_input"] || ""

      // Defer + do work + follow-up
      queueMicrotask(async () => {
        try {
          if (!config.serviceBotToken || !config.backendUrl) throw new Error("Server misconfigured")
          await postJson(
            `${config.backendUrl}/api/projects/${projectId}/progress`,
            { title, description, callerDiscordId: userId },
            { Authorization: `Bearer ${config.serviceBotToken}` },
          )

          // Public channel note
          await sendFollowup(
            body.token,
            [
              `📝 **${projectName}** — recent update from <@${userId}>`,
              `**Title:** ${title}`,
              description ? `**Description:** ${description}` : `**Description:** _none_`,
            ].join("\n"),
            false,
          )

          // Ephemeral ack
          await sendFollowup(body.token, `✅ Posted a recent update to **${projectName}**.`, true)
        } catch (err: any) {
          await sendFollowup(body.token, `❌ Error: ${err?.message || "failed to post update"}`, true)
        }
      })

      // Discord wants an immediate ACK
      return NextResponse.json({ type: InteractionCallbackType.DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE })
    }

    return NextResponse.json({
      type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
      data: { content: "Unknown modal.", flags: EPHEMERAL },
    })
  }

  // Fallback
  return NextResponse.json({
    type: InteractionCallbackType.CHANNEL_MESSAGE_WITH_SOURCE,
    data: { content: "Unsupported interaction.", flags: EPHEMERAL },
  })
}
