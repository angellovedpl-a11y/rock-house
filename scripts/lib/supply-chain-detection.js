const fs = require('fs');
const path = require('path');

function scanPnpmWorkspace(targetRoot, hasPackageJson, addFinding) {
  if (!hasPackageJson) return;
  const workspacePath = path.join(targetRoot, 'pnpm-workspace.yaml');
  if (!fs.existsSync(workspacePath)) return;

  const content = fs.readFileSync(workspacePath, 'utf8');
  if (!/^packages\s*:/m.test(content)) {
    addFinding(
      'Medio',
      'D2',
      'Supply Chain',
      'pnpm-workspace.yaml',
      1,
      'pnpm-workspace.yaml has no packages field; pnpm audit may fail before checking advisories.',
      'Add a packages field such as packages: ["."] or remove pnpm-workspace.yaml if this is not a workspace.'
    );
  }
}

module.exports = {
  scanPnpmWorkspace
};
