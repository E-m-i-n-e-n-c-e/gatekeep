import { readFileSync } from "fs";
import path from "path";

import { Marked, type Tokens } from "marked";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Docs: Gatekeep",
  description:
    "How Gatekeep works, from the Linux pieces to a packet's path, rate limiting and the live lab, plus the policy format, API, benchmark and limitations.",
};

const GROUPS = [
  { title: "Understand it", file: "guide.md" },
  { title: "Reference", file: "reference.md" },
];

const slug = (text: string) =>
  text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");

type Inline = { parser: { parseInline: (t: Tokens.Generic[]) => string } };

// Rendered at build time; the page ships as static HTML.
function render(file: string) {
  const source = readFileSync(path.join(process.cwd(), "content", file), "utf8");
  const toc: { id: string; text: string }[] = [];
  const marked = new Marked({
    renderer: {
      heading(this: Inline, { tokens, depth, text }: Tokens.Heading) {
        const id = slug(text);
        if (depth === 2) toc.push({ id, text });
        return `<h${depth} id="${id}">${this.parser.parseInline(tokens)}</h${depth}>`;
      },
      table(this: Inline, token: Tokens.Table) {
        const cell = (c: Tokens.TableCell, tag: string) => `<${tag}>${this.parser.parseInline(c.tokens)}</${tag}>`;
        const head = `<tr>${token.header.map((c) => cell(c, "th")).join("")}</tr>`;
        const body = token.rows.map((r) => `<tr>${r.map((c) => cell(c, "td")).join("")}</tr>`).join("");
        return `<div class="table-scroll"><table><thead>${head}</thead><tbody>${body}</tbody></table></div>`;
      },
    },
  });
  const html = marked.parse(source, { async: false }) as string;
  return { html, toc };
}

function Contents({ groups }: { groups: { title: string; toc: { id: string; text: string }[] }[] }) {
  return (
    <>
      {groups.map((g) => (
        <div key={g.title} className="docs-group">
          <h2>{g.title}</h2>
          <ol>
            {g.toc.map((h) => (
              <li key={h.id}>
                <a href={`#${h.id}`}>{h.text}</a>
              </li>
            ))}
          </ol>
        </div>
      ))}
    </>
  );
}

export default function DocsPage() {
  const groups = GROUPS.map((g) => ({ title: g.title, ...render(g.file) }));
  return (
    <div className="wrap docs">
      <aside className="docs-toc" aria-label="On this page">
        <h1>Docs</h1>
        <div className="docs-toc-full">
          <Contents groups={groups} />
        </div>
        <details className="docs-toc-compact">
          <summary>Contents</summary>
          <Contents groups={groups} />
        </details>
      </aside>
      <article className="prose">
        {groups.map((g) => (
          <section key={g.title} className="docs-part" aria-label={g.title}>
            <p className="docs-part-title">{g.title}</p>
            <div dangerouslySetInnerHTML={{ __html: g.html }} />
          </section>
        ))}
      </article>
    </div>
  );
}
