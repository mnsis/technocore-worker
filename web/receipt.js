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
    `File: ${data.fileStatus}`, "", "Checked through Technocore",
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

export function drawReceipt(canvas, data, includeDid = true) {
  canvas.width = 1200; canvas.height = 675;
  const context = canvas.getContext("2d");
  context.fillStyle = "#080b11"; context.fillRect(0, 0, 1200, 675);
  context.fillStyle = "#101722"; context.fillRect(55, 45, 1090, 585);
  context.fillStyle = "#63cce5"; context.fillRect(55, 45, 7, 585);
  canvasText(context, "TECHNOCORE WORKER", 100, 91, { font: "700 18px system-ui", color: "#63cce5" });
  canvasText(context, "CHECK RECEIPT", 100, 142, { font: "750 42px system-ui", color: "#eef4fb" });
  canvasText(context, `RECEIPT ${data.receiptId}`, 1100, 93, { font: "700 17px ui-monospace", color: "#8e9aab", align: "right" });
  canvasText(context, "REPOSITORY", 100, 204, { font: "700 14px system-ui", color: "#738094" });
  canvasText(context, data.repository, 100, 239, { font: "650 28px system-ui", color: "#eef4fb", maxWidth: 940 });
  canvasText(context, "COMMIT", 100, 288, { font: "700 14px system-ui", color: "#738094" });
  canvasText(context, abbreviate(data.commit, 12, 8), 100, 322, { font: "600 24px ui-monospace", color: "#b9c5d6" });
  const rows = [["REPOSITORY", data.repositoryStatus], ["COMMIT", data.commitStatus], ["FILE", data.fileStatus]];
  rows.forEach(([label, value], index) => {
    const y = 385 + index * 48;
    canvasText(context, label, 100, y, { font: "700 15px system-ui", color: "#8794a7" });
    const color = value === "CONFIRMED" ? "#62d39f" : value === "UNAVAILABLE" ? "#e2b15d" : "#a9b4c3";
    canvasText(context, value, 550, y, { font: "750 16px ui-monospace", color });
  });
  canvasText(context, "Checked through Technocore", 100, 555, { font: "650 18px system-ui", color: "#dce5f0" });
  canvasText(context, `Worker  ${abbreviate(data.workerDid)}`, 100, 588, { font: "500 14px ui-monospace", color: "#8e9aab" });
  if (includeDid) canvasText(context, `Requester  ${abbreviate(data.requesterDid)}`, 1100, 555, { font: "500 14px ui-monospace", color: "#8e9aab", align: "right" });
  else canvasText(context, "Requester DID hidden", 1100, 555, { font: "500 14px system-ui", color: "#8e9aab", align: "right" });
  canvasText(context, "Independent community project · Not affiliated with or endorsed by FLOP Labs", 1100, 588, { font: "500 12px system-ui", color: "#626f80", align: "right" });
  return canvas;
}
