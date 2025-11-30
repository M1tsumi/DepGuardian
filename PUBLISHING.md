# Publishing Checklist

This document outlines the steps required to publish DepGuardian to npm and GitHub.

## Pre-Publishing Checklist

### ✅ Code Quality
- [ ] All tests pass: `npm test`
- [ ] Build succeeds: `npm run build`
- [ ] Linting passes: `npm run lint`
- [ ] Code formatted: `npm run format`
- [ ] Coverage is acceptable: `npm run test:coverage`

### ✅ Documentation
- [ ] README is up to date
- [ ] CHANGELOG is updated for this version
- [ ] LICENSE is present and correct
- [ ] All API changes are documented

### ✅ Package Configuration
- [ ] package.json has correct version
- [ ] package.json has correct files array
- [ ] package.json has proper publishing config
- [ ] .gitignore excludes development files
- [ ] .npmignore excludes unnecessary files

### ✅ Security & Dependencies
- [ ] No known vulnerabilities in dependencies
- [ ] All dependencies are up to date
- [ ] API keys and secrets are not included
- [ ] Environment variables are properly documented

## Publishing Steps

### 1. Update Version
```bash
# Update version in package.json
npm version patch  # or minor/major

# This will:
# - Update package.json version
# - Create git tag
# - Run prepublishOnly script
```

### 2. Final Testing
```bash
# Clean install and test
rm -rf node_modules dist
npm install
npm run build
npm test

# Test CLI functionality
node dist/cli.js --version
node dist/cli.js scan tests/fixtures/suspicious-project
```

### 3. Dry Run (Optional)
```bash
# Pack without publishing
npm pack

# Test the packed package
tar -xzf depguardian-cli-1.0.0.tgz
cd package
npm install -g .
depguardian --version
```

### 4. Publish to npm
```bash
# Login to npm (if not already)
npm login

# Publish
npm publish

# For scoped packages with public access
npm publish --access public
```

### 5. GitHub Release
```bash
# Push changes and tags
git push origin main
git push origin --tags

# Create GitHub release through UI or CLI
gh release create v1.0.0 --title "v1.0.0" --notes "See CHANGELOG.md for details"
```

## Post-Publishing Checklist

### ✅ Verification
- [ ] Package is available on npm: `npm info @depguardian/cli`
- [ ] Installation works: `npm install -g @depguardian/cli`
- [ ] CLI functionality works: `depguardian --version`
- [ ] Documentation is accessible on npm

### ✅ Announcements
- [ ] GitHub release created
- [ ] Release notes published
- [ ] Social media announcements (optional)
- [ ] Community notifications (optional)

## Environment Setup for Publishing

### Required Accounts
- npm account with publishing permissions for @depguardian scope
- GitHub account with push access to repository

### Required Environment Variables
```bash
# For npm publishing
NPM_TOKEN=your_npm_token

# For GitHub releases (optional)
GITHUB_TOKEN=your_github_token
```

### GitHub Actions Setup
The project includes GitHub Actions for:
- Running tests on PRs
- Building and testing on push
- Publishing releases (when tagged)

## Troubleshooting

### Common Issues

#### 1. "403 Forbidden" from npm
- Check if you're logged in: `npm whoami`
- Verify you have permissions for the @depguardian scope
- Use `--access public` for scoped packages

#### 2. "Package name already exists"
- The package name is taken
- Choose a different name or scope
- For scoped packages: `@your-org/depguardian`

#### 3. "Files not included in package"
- Check the `files` array in package.json
- Verify .gitignore isn't excluding necessary files
- Use `npm pack --dry-run` to check included files

#### 4. "Build fails during publishing"
- Check the `prepublishOnly` script
- Ensure TypeScript compilation succeeds
- Verify all dependencies are installed

### Recovery Steps

If publishing fails:
1. Check the error message carefully
2. Fix the underlying issue
3. Increment version if necessary
4. Try publishing again

## Maintenance

### Regular Updates
- Update dependencies regularly
- Monitor for security vulnerabilities
- Keep documentation current
- Respond to issues and PRs promptly

### Version Management
- Follow semantic versioning
- Update CHANGELOG for each release
- Create git tags for releases
- Maintain backwards compatibility when possible

---

## Quick Publishing Commands

```bash
# Complete publishing workflow
npm version patch
npm run test
npm run build
npm publish --access public
git push origin main --tags
gh release create v$(npm pkg get version | tr -d '"') --title "v$(npm pkg get version | tr -d '"')" --notes "See CHANGELOG.md"
```

Remember to replace `patch` with `minor` or `major` as appropriate for the changes in the release.
