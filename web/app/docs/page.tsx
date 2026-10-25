import { readFileSync } from "fs";
import path from "path";

import { Marked, type Tokens } from "marked";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Docs: Gatekeep",
  description: "How Gatekeep works: the packet path, verdicts, policy format, control API, benchmark and limitations.",
};

const slug = (text: string) =>
  text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");

// Rendered at build time; the page ships as static HTML.
function render() {
  const source = readFileSync(path.join(process.cwd(), "content", "docs.md"), "utf8");
  const toc: { id: string; text: string }[] = [];
  const marked = new Marked({
    renderer: {
      heading(this: { parser: { parseInline: (t: Tokens.Heading["tokens"]) => string } }, { tokens, depth, text }: Tokens.Heading) {
        const id = slug(text);
        if (depth === 2) toc.push({ id, text });
        return `<h${depth} id="${id}">${this.parser.parseInline(tokens)}</h${depth}>`;
      },
      table(this: unknown, token: Tokens.Table) {
        const cell = (c: Tokens.TableCell, tag: string) => `<${tag}>${(this as { parser: { parseInline: (t: Tokens.TableCell["tokens"]) => string } }).parser.parseInline(c.tokens)}</${tag}>`;
        const head = `<tr>${token.header.map((c) => cell(c, "th")).join("")}</tr>`;
        const body = token.rows.map((r) => `<tr>${r.map((c) => cell(c, "td")).join("")}</tr>`).join("");
        return `<div class="table-scroll"><table><thead>${head}</thead><tbody>${body}</tbody></table></div>`;
      },
    },
  });
  const html = marked.parse(source, { async: false }) as string;
  return { html, toc };
}

export default function DocsPage() {
  const { html, toc } = render();
  return (
    <div className="wrap docs">
      <aside className="docs-toc" aria-label="On this page">
        <h1>Docs</h1>
        <ol>
          {toc.map((h) => (
            <li key={h.id}>
              <a href={`#${h.id}`}>{h.text}</a>
            </li>
          ))}
        </ol>
      </aside>
      <article className="prose" dangerouslySetInnerHTML={{ __html: html }} />
    </div>
  );
}
