---
title: "Documentation"
description: "Guide for updating cidrx documentation"
summary: "How to build and update the Hugo-based documentation site"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 510
toc: true
seo:
  title: "Contributing to cidrx Documentation"
  description: "Learn how to update the cidrx documentation site"
  canonical: ""
  noindex: false
---

cidrx documentation uses [Hugo](https://gohugo.io/) extended with the [Thulite/Doks](https://github.com/thuliteio/doks) theme.

## Local Development

### Start Server

```bash
cd docs
hugo server --environment development
```

Access at: http://localhost:1313/

### Build for Production

```bash
cd docs
HUGO_ENV=production hugo --minify --gc
```

## Page Structure

Every page needs front matter:

```yaml
---
title: "Page Title"
description: "Brief description"
summary: "Longer summary for search"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 100
toc: true
---
```

### Weight System

Controls page order (lower = first):

- Getting Started: 100-120
- Usage: 200-240
- Configuration: 300-350
- Advanced: 400-450
- Contributing: 500-550
- Guides: 800-850

## Writing Content

### Code Blocks

````markdown
```bash
./cidrx static --logfile access.log --plain
```
````

Supported: `bash`, `go`, `toml`, `yaml`, `json`, `nginx`

### Internal Links

```markdown
[Link Text]({{</* relref "/docs/section/page/" */>}})
```

Examples:

```markdown
See [Installation]({{< relref "/docs/getting-started/installation/" >}})
Learn about [Live Mode]({{< relref "/docs/usage/live-mode/" >}})
```

Always use trailing slash for section links.

### Images

```markdown
![Alt text](/images/screenshot.png)
```

Place images in: `docs/static/images/`

## Common Tasks

### Create New Page

```bash
cd docs
hugo new content/docs/section/page-name.md
```

### Update Existing Page

1. Edit the markdown file
2. Update `lastmod` date
3. Test with `hugo server`

### Add New Section

```bash
mkdir -p docs/content/docs/new-section
hugo new content/docs/new-section/_index.md
```

Set appropriate weight in front matter.

## Deployment

Documentation deploys automatically via GitHub Actions when pushed to `main`.

Workflow: `.github/workflows/docs.yml`

## Documentation Checklist

Before submitting docs PR:

- [ ] Ran `hugo server` and verified changes
- [ ] Updated `lastmod` date
- [ ] Tested all code examples
- [ ] Used appropriate weight for ordering

## Next Steps

Return to [Contributing Overview]({{< relref "/docs/contributing/" >}}) for development workflow.
