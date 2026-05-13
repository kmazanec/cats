"""Minimum-viable OOXML part templates.

A ``.docx`` is a ZIP archive containing XML parts. The smallest valid
file Word will open and python-docx will parse has four parts:

- ``[Content_Types].xml`` — declares MIME types for each path pattern.
- ``_rels/.rels`` — package-level relationship: root → document.
- ``word/document.xml`` — the actual body.
- ``word/_rels/document.xml.rels`` — document-level relationships
  (added per technique when needed: header, footer, footnotes,
  comments, settings).

Techniques layer additional parts on top: ``word/header1.xml``,
``word/footer1.xml``, ``word/footnotes.xml``, ``word/comments.xml``,
``docProps/core.xml``, ``word/settings.xml``. Each addition needs both
a content-type override and a relationship.
"""

from __future__ import annotations

# Namespace URIs used across every part.
NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "ct": "http://schemas.openxmlformats.org/package/2006/content-types",
    "rels": "http://schemas.openxmlformats.org/package/2006/relationships",
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
}

W_NS = NS["w"]
R_NS = NS["r"]

# Content-Types content. Overrides are appended per technique.
CONTENT_TYPES_BASE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""

# Override fragments per optional part.
OVERRIDES = {
    "header": '  <Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>',
    "footer": '  <Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>',
    "footnotes": '  <Override PartName="/word/footnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"/>',
    "comments": '  <Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>',
    "settings": '  <Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>',
    "core_properties": '  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>',
}

# Package-root relationship — always points root → document.
RELS_ROOT = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rIdCore" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>"""

# Relationship target types per optional part.
REL_TYPES = {
    "header": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/header",
    "footer": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer",
    "footnotes": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/footnotes",
    "comments": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments",
    "settings": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings",
}


def content_types_xml(extras: list[str]) -> str:
    """Render [Content_Types].xml with the given optional overrides."""
    if not extras:
        return CONTENT_TYPES_BASE
    insert = "\n".join(OVERRIDES[k] for k in extras)
    return CONTENT_TYPES_BASE.replace("</Types>", f"{insert}\n</Types>")


def document_rels_xml(rels: list[tuple[str, str, str]]) -> str:
    """Render word/_rels/document.xml.rels. ``rels`` is a list of
    ``(rId, target_part, kind)`` tuples; ``kind`` indexes ``REL_TYPES``."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">',
    ]
    for rid, target, kind in rels:
        lines.append(f'  <Relationship Id="{rid}" Type="{REL_TYPES[kind]}" Target="{target}"/>')
    lines.append("</Relationships>")
    return "\n".join(lines)
