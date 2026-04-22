import fs from "node:fs";
import path from "node:path";

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function main() {
  if (process.platform !== "darwin") return;

  const repoRoot = process.cwd();
  const tauriConfigPath = path.join(repoRoot, "src-tauri", "tauri.conf.json");
  const tauriConfig = readJson(tauriConfigPath);

  const productName = tauriConfig.productName;
  if (!productName) {
    throw new Error(`缺少 productName：${tauriConfigPath}`);
  }

  const srcIcon = path.join(repoRoot, "src-tauri", "icons", "icon.icns");
  if (!fs.existsSync(srcIcon)) {
    throw new Error(`找不到源图标：${srcIcon}`);
  }

  const appBundlePath = path.join(
    repoRoot,
    "src-tauri",
    "target",
    "debug",
    "bundle",
    "macos",
    `${productName}.app`,
  );

  const dstIcon = path.join(appBundlePath, "Contents", "Resources", "icon.icns");
  if (!fs.existsSync(dstIcon)) {
    // 第一次运行时可能还没生成 debug .app，这里直接跳过即可。
    return;
  }

  fs.copyFileSync(srcIcon, dstIcon);
}

main();

