# 4lock-core Documentation

## Structure

```
docs/
├── README.md                          ← You are here
├── architecture/
│   ├── OVERVIEW.md                    ← System purpose, layout, design principles
│   ├── CRATE_ARCHITECTURE.md          ← Module layout for blob, container, vappcore
│   └── NAMING.md                      ← Naming glossary (vapp, vappd, vappcore, etc.)
├── development/
│   └── DEVELOPMENT_GUIDE.md           ← Build, run, test, Makefile, container workflow
└── troubleshooting/
    └── BLOB_502_TROUBLESHOOTING.md    ← Blob 502 Bad Gateway diagnosis and fixes
```

## AI Assistant Support

| Tool | Entry Point | Docs Source |
|------|------------|-------------|
| **Cursor** | `.cursorrules` | `docs/` |
| **Claude Code** | `CLAUDE.md` | `docs/` |

Both tools share the same documentation in `docs/`.

## Quick Links

### Architecture
- [System Overview](architecture/OVERVIEW.md)
- [Crate Architecture](architecture/CRATE_ARCHITECTURE.md) — blob vs container vs vappcore
- [Naming Glossary](architecture/NAMING.md) — vapp, vappd, vappcore terminology

### Development
- [Development Guide](development/DEVELOPMENT_GUIDE.md) — Build, run, test, Makefile

### Troubleshooting
- [Blob 502 Bad Gateway](troubleshooting/BLOB_502_TROUBLESHOOTING.md) — VM diagnostics, DNS, mirrors
