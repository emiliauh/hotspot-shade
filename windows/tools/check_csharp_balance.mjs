// A small C# delimiter checker. It is not a compiler. It catches an
// unbalanced brace, parenthesis, or bracket before a Windows build.
// It understands comments, normal strings, verbatim strings, and char
// literals. It does not understand interpolated strings with braces.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const root = process.argv[2] || "windows";
const files = [];
function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (name === "bin" || name === "obj" || name === ".vs") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path);
    else if (name.endsWith(".cs")) files.push(path);
  }
}
walk(root);

let failed = false;
for (const file of files) {
  const text = readFileSync(file, "utf8");
  if (!text.endsWith("\n")) {
    console.error(`FAIL ${file}: no final newline`);
    failed = true;
  }
  const stack = [];
  const pairs = { "}": "{", ")": "(", "]": "[" };
  let line = 1;
  let index = 0;
  let state = "code";
  while (index < text.length) {
    const ch = text[index];
    const next = text[index + 1];
    if (ch === "\n") line++;
    if (state === "line-comment") {
      if (ch === "\n") state = "code";
      index++;
      continue;
    }
    if (state === "block-comment") {
      if (ch === "*" && next === "/") {
        state = "code";
        index += 2;
        continue;
      }
      index++;
      continue;
    }
    if (state === "string") {
      if (ch === "\\") {
        index += 2;
        continue;
      }
      if (ch === "\"") state = "code";
      index++;
      continue;
    }
    if (state === "verbatim") {
      if (ch === "\"" && next === "\"") {
        index += 2;
        continue;
      }
      if (ch === "\"") state = "code";
      index++;
      continue;
    }
    if (state === "char") {
      if (ch === "\\") {
        index += 2;
        continue;
      }
      if (ch === "'") state = "code";
      index++;
      continue;
    }
    if (ch === "/" && next === "/") {
      state = "line-comment";
      index += 2;
      continue;
    }
    if (ch === "/" && next === "*") {
      state = "block-comment";
      index += 2;
      continue;
    }
    if (ch === "@" && next === "\"") {
      state = "verbatim";
      index += 2;
      continue;
    }
    if (ch === "\"") {
      state = "string";
      index++;
      continue;
    }
    if (ch === "'") {
      state = "char";
      index++;
      continue;
    }
    if (ch === "{" || ch === "(" || ch === "[") {
      stack.push({ ch, line });
    } else if (ch === "}" || ch === ")" || ch === "]") {
      const open = stack.pop();
      if (!open || open.ch !== pairs[ch]) {
        console.error(`FAIL ${file}:${line}: unmatched ${ch}`);
        failed = true;
        break;
      }
    }
    index++;
  }
  if (state === "block-comment") {
    console.error(`FAIL ${file}: unterminated block comment`);
    failed = true;
  }
  if (state === "string" || state === "verbatim" || state === "char") {
    console.error(`FAIL ${file}: unterminated literal`);
    failed = true;
  }
  if (stack.length > 0) {
    console.error(`FAIL ${file}:${stack[stack.length - 1].line}: unclosed ${stack[stack.length - 1].ch}`);
    failed = true;
  }
}

if (failed) process.exit(1);
console.log(`C# delimiter check passed for ${files.length} files`);
