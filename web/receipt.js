export function receiptId(digest) {
  if (!/^[0-9a-f]{64}$/i.test(digest || "")) throw new Error("Receipt digest is unavailable.");
  const short = digest.slice(0, 8).toUpperCase();
  return `${short.slice(0, 4)}-${short.slice(4)}`;
}

export function abbreviate(value, start = 14, end = 8) {
  if (!value || value.length <= start + end + 1) return value || "";
  return `${value.slice(0, start)}…${value.slice(-end)}`;
}

export function filePresentation(result, requestedPath) {
  return requestedPath ? result.checks?.requested_file?.status || "UNAVAILABLE" : "NOT REQUESTED";
}

export function copyReceiptText(data) {
  return [
    "Technocore check", "", data.repository, data.commit, "",
    `Repository: ${data.repositoryStatus}`, `Commit: ${data.commitStatus}`,
    ...(data.path ? [`File: ${data.fileStatus}`] : []),
    "", "Checked through Technocore",
    `Receipt: ${data.receiptId}`, "", `Worker: ${abbreviate(data.workerDid)}`,
  ].join("\n");
}

function shareRepository(repository) {
  if (repository.length <= 58) return repository;
  const [owner, name = ""] = repository.split("/", 2);
  return `${owner.slice(0, 18)}…/${name.slice(0, 34)}…`;
}

export function xShareText(data, origin) {
  return [
    "Checked a GitHub commit through Technocore.", "", shareRepository(data.repository),
    "Repository ✓", "Commit ✓", "", `Receipt ${data.receiptId}`, "", origin,
  ].join("\n");
}

function canvasText(context, text, x, y, style) {
  context.font = style.font;
  context.fillStyle = style.color;
  context.textAlign = style.align || "left";
  context.fillText(text, x, y, style.maxWidth);
}

const DISPLAY_FONT = 'Arial, "Helvetica Neue", sans-serif';
const MONO_FONT = '"Courier New", Courier, monospace';

function wrapCanvasText(context, text, maxWidth, maxLines) {
  const preferred = text.includes("/") ? [`${text.split("/")[0]}/`, text.slice(text.indexOf("/") + 1)] : [text];
  const lines = [];
  for (const part of preferred) {
    let remaining = part;
    while (remaining && lines.length < maxLines) {
      let end = remaining.length;
      while (end > 1 && context.measureText(remaining.slice(0, end)).width > maxWidth) end -= 1;
      if (lines.length === maxLines - 1 && end < remaining.length) { lines.push(`${remaining.slice(0, Math.max(1, end - 1))}…`); return lines; }
      lines.push(remaining.slice(0, end)); remaining = remaining.slice(end);
    }
  }
  return lines;
}

export async function drawReceipt(canvas, data, includeDid = true) {
  if (document.fonts?.ready) await document.fonts.ready;
  canvas.width = 1200; canvas.height = 675;
  const context = canvas.getContext("2d");
  context.fillStyle = "#080c12"; context.fillRect(0, 0, 1200, 675);
  context.fillStyle = "#0d141d"; context.fillRect(36, 32, 1128, 611);
  context.fillStyle = "#63cce5"; context.fillRect(74, 64, 44, 3);
  canvasText(context, "TECHNOCORE WORKER", 74, 98, { font: `700 17px ${DISPLAY_FONT}`, color: "#d7e2ed" });
  canvasText(context, data.receiptId, 1125, 98, { font: `700 17px ${MONO_FONT}`, color: "#8291a4", align: "right" });
  context.fillStyle = "#25303d"; context.fillRect(74, 122, 1051, 1);
  canvasText(context, "GitHub commit checked", 74, 161, { font: `600 18px ${DISPLAY_FONT}`, color: "#8190a3" });

  const repositoryFontSize = data.repository.length > 95 ? 40 : 48;
  context.font = `700 ${repositoryFontSize}px ${DISPLAY_FONT}`;
  const repositoryLines = wrapCanvasText(context, data.repository, 930, 3);
  repositoryLines.forEach((line, index) => canvasText(context, line, 74, 216 + index * 50, { font: `700 ${repositoryFontSize}px ${DISPLAY_FONT}`, color: index === 0 && line.endsWith("/") ? "#63cce5" : "#f0f5fa" }));
  const repositoryBottom = 216 + (repositoryLines.length - 1) * 50;
  canvasText(context, abbreviate(data.commit, 12, 8), 74, repositoryBottom + 42, { font: `600 20px ${MONO_FONT}`, color: "#9eacbd" });

  const rows = [["REPOSITORY", data.repositoryStatus], ["COMMIT", data.commitStatus]];
  if (data.path) rows.push(["FILE", data.fileStatus]);
  const statusY = Math.max(390, repositoryBottom + 95);
  rows.forEach(([label, value], index) => {
    const x = 74 + index * 250; const y = statusY;
    const color = value === "CONFIRMED" ? "#62d39f" : value === "UNAVAILABLE" ? "#e2b15d" : "#a9b4c3";
    canvasText(context, value === "CONFIRMED" ? "✓" : "—", x, y, { font: `700 18px ${DISPLAY_FONT}`, color });
    canvasText(context, label, x + 26, y, { font: `700 13px ${DISPLAY_FONT}`, color: "#8290a2" });
    canvasText(context, value, x + 26, y + 25, { font: `700 15px ${MONO_FONT}`, color });
  });
  canvasText(context, `Checked through Technocore · ${data.duration}`, 74, 534, { font: `600 17px ${DISPLAY_FONT}`, color: "#d4dde8" });
  if (includeDid) canvasText(context, `Requester  ${abbreviate(data.requesterDid)}`, 74, 568, { font: `500 13px ${MONO_FONT}`, color: "#748296" });
  else canvasText(context, "Requester DID hidden", 74, 568, { font: `500 13px ${DISPLAY_FONT}`, color: "#748296" });
  canvasText(context, `Worker ${abbreviate(data.workerDid, 10, 6)}`, 1125, 534, { font: `500 12px ${MONO_FONT}`, color: "#657387", align: "right" });
  context.fillStyle = "#25303d"; context.fillRect(74, 596, 1051, 1);
  canvasText(context, "Independent community tool · Not affiliated with FLOP Labs", 74, 622, { font: `500 12px ${DISPLAY_FONT}`, color: "#5f6d80" });
  return canvas;
}
