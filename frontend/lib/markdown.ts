// Lightweight zero-dependency Markdown parser and documentation indexer

export interface DocSection {
  id: string;
  title: string;
  level: number;
  content: string;
  rawBlocks: MarkdownBlock[];
  subsections?: DocSection[];
}

export type MarkdownBlock =
  | { type: 'heading'; level: number; text: string; id: string }
  | { type: 'paragraph'; text: string }
  | { type: 'alert'; variant: 'note' | 'tip' | 'important' | 'warning' | 'caution'; title: string; text: string }
  | { type: 'code'; language: string; code: string }
  | { type: 'table'; headers: string[]; rows: string[][] }
  | { type: 'list'; ordered: boolean; items: string[] }
  | { type: 'divider' };

// Helper to generate clean slugs from Arabic and English headings
export function slugify(text: string): string {
  // Remove markdown formatting characters
  const clean = text
    .replace(/[#*`_~[\]()]/g, '')
    .trim()
    .toLowerCase();

  // Match existing explicit anchor tags if parsed separately, else sanitize
  return clean
    .replace(/[^\w\u0600-\u06FF\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-');
}

// Parse raw markdown string into structured blocks and hierarchical sections
export function parseMarkdownGuide(rawMarkdown: string): {
  sections: DocSection[];
  tableOfContents: { id: string; title: string; level: number }[];
} {
  const lines = rawMarkdown.split(/\r?\n/);
  const sections: DocSection[] = [];
  const toc: { id: string; title: string; level: number }[] = [];

  let currentSection: DocSection = {
    id: 'intro',
    title: 'المقدمة',
    level: 1,
    content: '',
    rawBlocks: [],
  };

  let pendingAnchorId = '';
  let i = 0;

  while (i < lines.length) {
    const startIndex = i;
    const line = lines[i];

    // Check for HTML anchor tag like <a id="quick-start"></a>
    const anchorMatch = line.match(/<a\s+(?:id|name)=["']([^"']+)["']\s*><\/a>/i);
    if (anchorMatch) {
      pendingAnchorId = anchorMatch[1];
      i++;
      continue;
    }

    // Horizontal Rule
    if (/^(\*{3,}|-{3,}|_{3,})$/.test(line.trim())) {
      currentSection.rawBlocks.push({ type: 'divider' });
      currentSection.content += '\n';
      i++;
      continue;
    }

    // Code Block
    if (line.trim().startsWith('```')) {
      const lang = line.trim().slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // Skip closing ```
      const fullCode = codeLines.join('\n');
      currentSection.rawBlocks.push({
        type: 'code',
        language: lang || 'text',
        code: fullCode,
      });
      currentSection.content += ' ' + fullCode;
      continue;
    }

    // Headings (# Heading)
    const headingMatch = line.match(/^(#{1,6})\s+(.+)$/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      const rawTitle = headingMatch[2].trim();
      const sectionId = pendingAnchorId || slugify(rawTitle);
      pendingAnchorId = '';

      // Clean up title text for display (remove markdown symbols)
      const cleanTitle = rawTitle.replace(/[*_`]/g, '').trim();

      // Only top and mid-level headings create distinct navigatable sections
      if (level === 2) {
        if (currentSection.rawBlocks.length > 0 || currentSection.title !== 'المقدمة') {
          sections.push(currentSection);
        }
        currentSection = {
          id: sectionId,
          title: cleanTitle,
          level,
          content: cleanTitle,
          rawBlocks: [{ type: 'heading', level, text: cleanTitle, id: sectionId }],
        };
        toc.push({ id: sectionId, title: cleanTitle, level });
      } else {
        currentSection.rawBlocks.push({
          type: 'heading',
          level,
          text: cleanTitle,
          id: sectionId,
        });
        currentSection.content += ' ' + cleanTitle;
        if (level === 3) {
          toc.push({ id: sectionId, title: cleanTitle, level });
        }
      }

      i++;
      continue;
    }

    // Alert Callouts (> [!NOTE], > [!IMPORTANT], > [!WARNING], > [!TIP], > [!CAUTION]) or general blockquotes (>)
    if (line.trim().startsWith('>')) {
      const alertMatch = line.match(/^>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]/i);
      let variant: 'note' | 'tip' | 'important' | 'warning' | 'caution' = 'note';
      let title = 'ملاحظة تشغيلية';
      const alertLines: string[] = [];

      if (alertMatch) {
        variant = alertMatch[1].toLowerCase() as 'note' | 'tip' | 'important' | 'warning' | 'caution';
        title = variant.toUpperCase();
        i++;
      }

      while (i < lines.length && lines[i].trim().startsWith('>')) {
        alertLines.push(lines[i].replace(/^>\s?/, ''));
        i++;
      }

      const fullAlertText = alertLines.join('\n').trim();
      if (fullAlertText) {
        currentSection.rawBlocks.push({
          type: 'alert',
          variant,
          title,
          text: fullAlertText,
        });
        currentSection.content += ' ' + fullAlertText;
      }
      continue;
    }

    // Markdown Tables (| header | header |)
    if (line.trim().startsWith('|') && line.trim().endsWith('|')) {
      const tableLines: string[] = [];
      while (i < lines.length && lines[i].trim().startsWith('|') && lines[i].trim().endsWith('|')) {
        tableLines.push(lines[i].trim());
        i++;
      }

      if (tableLines.length >= 2) {
        const parseRow = (row: string) =>
          row
            .slice(1, -1)
            .split('|')
            .map((c) => c.trim());

        const headers = parseRow(tableLines[0]);
        // Skip separator line (e.g. |---|---|)
        const contentRows = tableLines.slice(2).map(parseRow);

        currentSection.rawBlocks.push({
          type: 'table',
          headers,
          rows: contentRows,
        });
        currentSection.content += ' ' + headers.join(' ') + ' ' + contentRows.flat().join(' ');
        continue;
      }
    }

    // Lists (unordered - / * or ordered 1.)
    if (/^(\s*[-*]|\s*\d+\.)\s+/.test(line)) {
      const isOrdered = /^\s*\d+\./.test(line);
      const items: string[] = [];

      while (i < lines.length && /^(\s*[-*]|\s*\d+\.)\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^(\s*[-*]|\s*\d+\.)\s+/, '').trim());
        i++;
      }

      currentSection.rawBlocks.push({
        type: 'list',
        ordered: isOrdered,
        items,
      });
      currentSection.content += ' ' + items.join(' ');
      continue;
    }

    // Empty Lines
    if (line.trim() === '') {
      i++;
      continue;
    }

    // Regular Paragraphs (collect consecutive non-empty lines)
    const paragraphLines: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== '' &&
      !lines[i].trim().startsWith('#') &&
      !lines[i].trim().startsWith('```') &&
      !lines[i].trim().startsWith('>') &&
      !lines[i].trim().startsWith('|') &&
      !/^(\s*[-*]|\s*\d+\.)\s+/.test(lines[i]) &&
      !lines[i].match(/<a\s+(?:id|name)=/i)
    ) {
      paragraphLines.push(lines[i].trim());
      i++;
    }

    if (paragraphLines.length > 0) {
      const fullPara = paragraphLines.join(' ');
      currentSection.rawBlocks.push({
        type: 'paragraph',
        text: fullPara,
      });
      currentSection.content += ' ' + fullPara;
      continue;
    }

    // Fallback: If no block matched or advanced, advance i safely by 1 line
    if (i === startIndex) {
      const fallbackText = lines[i].trim();
      if (fallbackText) {
        currentSection.rawBlocks.push({
          type: 'paragraph',
          text: fallbackText,
        });
        currentSection.content += ' ' + fallbackText;
      }
      i++;
    }
  }

  if (currentSection.rawBlocks.length > 0 || currentSection.title !== 'المقدمة') {
    sections.push(currentSection);
  }

  return { sections, tableOfContents: toc };
}

// In-memory instant search across parsed sections
export interface SearchResult {
  sectionId: string;
  sectionTitle: string;
  matchedText: string;
  score: number;
}

export function searchDocumentation(query: string, sections: DocSection[]): SearchResult[] {
  const cleanQuery = query.trim().toLowerCase();
  if (!cleanQuery) return [];

  const terms = cleanQuery.split(/\s+/).filter(Boolean);
  const results: SearchResult[] = [];

  for (const sec of sections) {
    let score = 0;
    let snippet = '';

    const titleLower = sec.title.toLowerCase();
    const contentLower = sec.content.toLowerCase();

    // Check title matches (higher weight)
    for (const term of terms) {
      if (titleLower.includes(term)) {
        score += 10;
      }
      if (contentLower.includes(term)) {
        score += 2;
      }
    }

    if (score > 0) {
      // Find representative snippet
      const firstTerm = terms[0];
      const matchIndex = contentLower.indexOf(firstTerm);
      if (matchIndex !== -1) {
        const start = Math.max(0, matchIndex - 60);
        const end = Math.min(sec.content.length, matchIndex + 120);
        snippet = (start > 0 ? '...' : '') + sec.content.slice(start, end).trim() + (end < sec.content.length ? '...' : '');
      } else {
        snippet = sec.content.slice(0, 150).trim() + '...';
      }

      results.push({
        sectionId: sec.id,
        sectionTitle: sec.title,
        matchedText: snippet,
        score,
      });
    }
  }

  return results.sort((a, b) => b.score - a.score);
}
