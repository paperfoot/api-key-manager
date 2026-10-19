#!/usr/bin/env python3
"""Render the README's terminal illustrations as SVG.

Output lines come from real AKM runs with a throwaway key. Run from the
repository root: python3 assets/terminals.py
"""

from html import escape
from pathlib import Path

INK, EDGE, BAR = "#14171A", "#2B3036", "#1B1F23"
CREAM, DIM, MUTED = "#F2EDE4", "#C9C3B8", "#7D848C"
BRASS, SAGE, RUST = "#D9A441", "#8FB39A", "#E07A5F"
FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"
SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
SIZE, LINE, PAD, TITLE = 14, 23, 22, 34
OUT = Path(__file__).resolve().parent


def spans(parts):
    """parts: list of (text, colour[, weight]) → tspans."""
    out = []
    for text, colour, *weight in parts:
        w = f' font-weight="{weight[0]}"' if weight else ""
        out.append(f'<tspan fill="{colour}"{w}>{escape(text)}</tspan>')
    return "".join(out)


def cmd(text):
    return [("$ ", BRASS, 700), (text, CREAM, 600)]


def window(x, y, w, title, lines):
    h = TITLE + PAD * 2 + LINE * len(lines) - (LINE - SIZE)
    dots = "".join(
        f'<circle cx="{x + 18 + i * 18}" cy="{y + TITLE / 2}" r="5.5" fill="{c}"/>'
        for i, c in enumerate(("#E5675F", "#E0B54A", "#6DBA6A"))
    )
    body = "".join(
        f'<text x="{x + PAD}" y="{y + TITLE + PAD + SIZE + i * LINE}" xml:space="preserve">{spans(parts)}</text>'
        for i, parts in enumerate(lines)
    )
    return h, (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{INK}" stroke="{EDGE}"/>'
        f'<path d="M{x} {y + 12}a12 12 0 0 1 12-12h{w - 24}a12 12 0 0 1 12 12v{TITLE - 12}h-{w}z" fill="{BAR}"/>'
        f'<line x1="{x}" y1="{y + TITLE}" x2="{x + w}" y2="{y + TITLE}" stroke="{EDGE}"/>'
        f'{dots}<text x="{x + w / 2}" y="{y + TITLE / 2 + 4.5}" text-anchor="middle" font-family="{SANS}" font-size="12.5" fill="{MUTED}">{escape(title)}</text>'
        f"{body}"
    )


def svg(w, h, inner, label):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
        f'role="img" aria-label="{escape(label)}" font-family="{FONT}" font-size="{SIZE}">'
        f"<title>{escape(label)}</title>{inner}</svg>\n"
    )


def agent_session():
    lines = [
        [("# The agent needs OpenAI for an eval. It looks up a name, not a value.", MUTED)],
        cmd("akm list --names-only | grep OPENAI"),
        [("OPENAI_API_KEY", DIM)],
        cmd("akm run --only OPENAI_API_KEY -- python eval.py"),
        [("client ready, key=", DIM), ("[REDACTED:OPENAI_API_KEY]", SAGE, 600)],
        [("eval: 42/42 passed", DIM)],
        [("", DIM)],
        [("# Same key, published to CI. Piped straight in, never printed.", MUTED)],
        cmd("akm stdin OPENAI_API_KEY -- gh secret set OPENAI_API_KEY"),
        [("✓ ", SAGE, 700), ("Set Actions secret OPENAI_API_KEY for paperfoot/app", DIM)],
    ]
    h, win = window(1, 1, 818, "agent session — ~/Projects/app", lines)
    return svg(820, h + 2, win, "An AI agent using akm list, akm run and akm stdin; the key is redacted in output")


def before_after():
    w, gap = 446, 28
    left = [
        cmd("cat .env"),
        [("OPENAI_API_KEY=", DIM), ("sk-proj-9fK…", RUST, 600)],
        [("STRIPE_SECRET_KEY=", DIM), ("sk_live_…", RUST, 600)],
        [("", DIM)],
        [("# Both values are now in the transcript,", MUTED)],
        [("# the provider's logs and every summary.", MUTED)],
    ]
    right = [
        cmd("akm run --only OPENAI_API_KEY \\"),
        [("    -- npm test", CREAM, 600)],
        [("✓ ", SAGE, 700), ("42 passed", DIM)],
        [("", DIM)],
        [("# The agent handled a name. The value went", MUTED)],
        [("# from Keychain straight into the test run.", MUTED)],
    ]
    top = 34
    h1, a = window(1, top, w, "without akm", left)
    _, b = window(w + gap + 1, top, w, "with akm", right)
    labels = (
        f'<text x="{1 + w / 2}" y="20" text-anchor="middle" font-family="{SANS}" font-size="15" font-weight="700" fill="{RUST}">✗  The agent reads .env</text>'
        f'<text x="{w + gap + 1 + w / 2}" y="20" text-anchor="middle" font-family="{SANS}" font-size="15" font-weight="700" fill="{SAGE}">✓  The agent runs akm</text>'
    )
    total = 2 * w + gap + 2
    return svg(total, top + h1 + 2, labels + a + b, "Without akm the agent reads keys from .env; with akm it runs the command by key name")


def how_it_works():
    W, H = 900, 270
    box = lambda x, y, w, h, title, sub, colour: (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{BAR}" stroke="{colour}" stroke-width="1.5"/>'
        f'<text x="{x + w / 2}" y="{y + 34}" text-anchor="middle" font-family="{SANS}" font-size="16" font-weight="700" fill="{CREAM}">{escape(title)}</text>'
        + "".join(
            f'<text x="{x + w / 2}" y="{y + 60 + i * 21}" text-anchor="middle" font-size="12.5" fill="{DIM}">{escape(s)}</text>'
            for i, s in enumerate(sub)
        )
    )
    arrow = lambda x1, x2, y, label, colour, back=False: (
        f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{colour}" stroke-width="2"/>'
        f'<path d="M{x2} {y}l{6 if back else -6} -5v10z" fill="{colour}"/>'
        f'<text x="{(x1 + x2) / 2}" y="{y - 9}" text-anchor="middle" font-size="12" fill="{colour}">{escape(label)}</text>'
    )
    inner = (
        f'<rect x="1" y="1" width="{W - 2}" height="{H - 2}" rx="14" fill="{INK}" stroke="{EDGE}"/>'
        + box(30, 36, 230, 112, "Agent", ["Claude Code, Codex,", "Gemini CLI, your scripts"], MUTED)
        + box(335, 36, 230, 112, "akm", ["reads the named keys", "from macOS Keychain"], BRASS)
        + box(640, 36, 230, 112, "Your command", ["gets them as env vars", "or on stdin"], SAGE)
        + arrow(262, 333, 80, "key names", BRASS)
        + arrow(567, 638, 80, "values", SAGE)
        + arrow(638, 567, 124, "output", DIM, back=True)
        + arrow(333, 262, 124, "redacted", DIM, back=True)
        + f'<text x="{W / 2}" y="196" text-anchor="middle" font-family="{SANS}" font-size="15" fill="{CREAM}">The agent sends names and gets results. Values stay out of its context.</text>'
        + f'<text x="{W / 2}" y="226" text-anchor="middle" font-size="12.5" fill="{MUTED}">No account · no server · no prompts · exit codes pass through · audit log of every run</text>'
    )
    return svg(W, H, inner, "How akm works: the agent sends key names, akm injects values into the command, and redacted output returns")


if __name__ == "__main__":
    for name, make in (("agent-session", agent_session), ("before-after", before_after), ("how-it-works", how_it_works)):
        (OUT / f"{name}.svg").write_text(make())
        print(f"assets/{name}.svg")
