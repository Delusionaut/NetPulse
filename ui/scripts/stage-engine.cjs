const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..", "..");
const dest = path.resolve(__dirname, "..", "engine-stage");
fs.rmSync(dest, { recursive: true, force: true });
fs.mkdirSync(dest, { recursive: true });
for (const name of fs.readdirSync(root)) {
  if (name.endsWith(".py")) {
    fs.copyFileSync(path.join(root, name), path.join(dest, name));
  }
}
fs.copyFileSync(path.join(root, "requirements.txt"), path.join(dest, "requirements.txt"));
console.log("staged engine into", dest);
