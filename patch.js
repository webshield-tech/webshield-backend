const fs = require('fs');
let code = fs.readFileSync('src/controllers/user-scan-controller.js', 'utf8');
code = code.replace(
  /if \(scanMode === "full"\) \{\s*args\.push\("--forms", "--crawl", "3", "--dump-all"\);\s*\} else \{\s*args\.push\("--forms", "--crawl", "1"\);\s*\}/,
  `if (scanMode === "full") {
      args.push("--dump-all");
      if (!sqlmapTarget.includes("?")) args.push("--forms", "--crawl", "3");
    } else {
      if (!sqlmapTarget.includes("?")) args.push("--forms", "--crawl", "1");
    }`
);
fs.writeFileSync('src/controllers/user-scan-controller.js', code);
