// sanitizeRichText renders runtime-provided text safely for the console.
//
// Every HTML character is escaped first, then ONLY <code>…</code> is
// re-allowed — the single markup construct leak-report details use. Any
// other tag, attribute, or script payload arrives as inert text. This is
// applied at the API boundary (leak-report route) AND again at render
// time (page.tsx) so a future caller that skips the first pass still
// cannot inject markup.
export function sanitizeRichText(input: unknown): string {
  const s = String(input ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
  return s.replace(/&lt;\/code&gt;/g, "</code>").replace(/&lt;code&gt;/g, "<code>");
}