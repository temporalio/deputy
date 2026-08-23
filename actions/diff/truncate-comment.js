'use strict';

const truncationNotice = '> Report truncated: see the workflow job summary for the full version.';

function truncateMarkdown(report, maxBytes) {
  if (!Number.isInteger(maxBytes) || maxBytes <= 0) {
    throw new RangeError('maxBytes must be a positive integer');
  }
  if (utf8Length(report) <= maxBytes) {
    return report;
  }

  const noticeSuffix = `\n\n${truncationNotice}`;
  let contentLimit = maxBytes - utf8Length(noticeSuffix);
  if (contentLimit <= 0) {
    return sliceUtf8(truncationNotice, maxBytes);
  }

  while (contentLimit > 0) {
    const prefix = completeLinePrefix(report, contentLimit);
    const closings = openDetails(prefix)
      .reverse()
      .map(indent => `${indent}</details>`)
      .join('\n');
    const candidate = [prefix, closings, truncationNotice]
      .filter(Boolean)
      .join('\n\n');
    const excess = utf8Length(candidate) - maxBytes;
    if (excess <= 0) {
      return candidate;
    }
    contentLimit -= excess;
  }

  return sliceUtf8(truncationNotice, maxBytes);
}

function encodeMarkdownOutput(report, maxUtf16Bytes) {
  if (!Number.isInteger(maxUtf16Bytes) || maxUtf16Bytes < 8) {
    throw new RangeError('maxUtf16Bytes must be an integer of at least 8');
  }

  const maxBase64Characters = Math.floor(maxUtf16Bytes / 2);
  const maxReportBytes = Math.floor(maxBase64Characters / 4) * 3;
  const markdown = truncateMarkdown(report, maxReportBytes);
  return Buffer.from(markdown, 'utf8').toString('base64');
}

module.exports = { encodeMarkdownOutput, truncateMarkdown, truncationNotice };

function completeLinePrefix(report, maxBytes) {
  const prefix = sliceUtf8(report, maxBytes);
  const boundary = prefix.lastIndexOf('\n');
  if (boundary < 0) {
    return '';
  }
  return prefix.slice(0, boundary).trimEnd();
}

function openDetails(markdown) {
  const stack = [];
  for (const line of markdown.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (/^<details(?:\s[^>]*)?>/i.test(trimmed)) {
      stack.push(line.match(/^\s*/)[0]);
    } else if (/^<\/details>\s*$/i.test(trimmed)) {
      stack.pop();
    }
  }
  return stack;
}

function utf8Length(value) {
  return Buffer.byteLength(value, 'utf8');
}

function sliceUtf8(value, maxBytes) {
  let bytes = 0;
  let result = '';
  for (const character of value) {
    const size = utf8Length(character);
    if (bytes + size > maxBytes) {
      break;
    }
    bytes += size;
    result += character;
  }
  return result;
}
