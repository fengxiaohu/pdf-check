from __future__ import annotations

from collections.abc import Iterable

from pypdf import PdfReader
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DictionaryObject,
    IndirectObject,
    StreamObject,
    TextStringObject,
)

from .types import TextFragment


def scan_pdf_text_fragments(path: str, include_fallback_object_strings: bool = True) -> list[TextFragment]:
    reader = PdfReader(path)
    fragments: list[TextFragment] = []

    _scan_page_content(reader, fragments)
    _scan_annotations(reader, fragments)
    _scan_document_metadata(reader, fragments)
    _scan_xmp_metadata(reader, fragments)
    _scan_forms(reader, fragments)
    _scan_embedded_files(reader, fragments)
    if include_fallback_object_strings:
        _scan_all_string_objects(reader, fragments)

    return _dedupe_fragments(fragments)


def _scan_page_content(reader: PdfReader, out: list[TextFragment]) -> None:
    for i, page in enumerate(reader.pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception:
            text = ""
        if not text.strip():
            continue

        page_ref = getattr(page, "indirect_reference", None)
        obj_id = getattr(page_ref, "idnum", None) if page_ref is not None else None
        out.append(
            TextFragment(
                text=text,
                location_type="content_stream",
                page=i,
                object_id=obj_id,
                source="page.extract_text",
            )
        )


def _scan_annotations(reader: PdfReader, out: list[TextFragment]) -> None:
    keys_to_check = ["/Contents", "/RC", "/T", "/Subj", "/TU"]
    for i, page in enumerate(reader.pages, start=1):
        annots = page.get("/Annots")
        if not annots:
            continue
        for annot in _iter_array(annots):
            annot_dict, obj_id = _resolve_indirect(annot)
            if not isinstance(annot_dict, DictionaryObject):
                continue
            for key in keys_to_check:
                value = annot_dict.get(key)
                if value is None:
                    continue
                text = _object_to_text(value)
                if text:
                    out.append(
                        TextFragment(
                            text=text,
                            location_type="annotation",
                            page=i,
                            object_id=obj_id,
                            source=f"annot:{key}",
                        )
                    )

            # Also scan arbitrary strings inside annotation dictionaries.
            for text in _walk_string_values(annot_dict):
                out.append(
                    TextFragment(
                        text=text,
                        location_type="annotation",
                        page=i,
                        object_id=obj_id,
                        source="annot:walk",
                    )
                )


def _scan_document_metadata(reader: PdfReader, out: list[TextFragment]) -> None:
    metadata = reader.metadata or {}
    info_obj, info_obj_id = _resolve_indirect(reader.trailer.get("/Info"))

    if isinstance(metadata, dict):
        for key, value in metadata.items():
            text = _object_to_text(value)
            if text:
                out.append(
                    TextFragment(
                        text=f"{key}: {text}",
                        location_type="metadata",
                        page=None,
                        object_id=info_obj_id,
                        source=f"info:{key}",
                    )
                )

    if isinstance(info_obj, DictionaryObject):
        for key, value in info_obj.items():
            text = _object_to_text(value)
            if text:
                out.append(
                    TextFragment(
                        text=f"{key}: {text}",
                        location_type="metadata",
                        page=None,
                        object_id=info_obj_id,
                        source=f"info-walk:{key}",
                    )
                )


def _scan_xmp_metadata(reader: PdfReader, out: list[TextFragment]) -> None:
    root = reader.trailer.get("/Root")
    if root is None:
        return

    root_dict, _ = _resolve_indirect(root)
    if not isinstance(root_dict, DictionaryObject):
        return

    md = root_dict.get("/Metadata")
    md_obj, md_obj_id = _resolve_indirect(md)
    if isinstance(md_obj, StreamObject):
        try:
            data = md_obj.get_data()
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        if text.strip():
            out.append(
                TextFragment(
                    text=text,
                    location_type="metadata",
                    page=None,
                    object_id=md_obj_id,
                    source="xmp-stream",
                )
            )


def _scan_forms(reader: PdfReader, out: list[TextFragment]) -> None:
    root = reader.trailer.get("/Root")
    root_dict, _ = _resolve_indirect(root)
    if not isinstance(root_dict, DictionaryObject):
        return

    acro = root_dict.get("/AcroForm")
    acro_dict, acro_id = _resolve_indirect(acro)
    if not isinstance(acro_dict, DictionaryObject):
        return

    keys_to_check = ["/T", "/TU", "/V", "/DV", "/TM", "/RV"]
    for field_ref in _iter_array(acro_dict.get("/Fields")):
        _scan_form_field_recursive(field_ref, out, keys_to_check)

    # XFA may be array of packet-name / stream pairs, or a stream.
    xfa = acro_dict.get("/XFA")
    xfa_obj, _ = _resolve_indirect(xfa)
    if isinstance(xfa_obj, ArrayObject):
        for item in xfa_obj:
            item_obj, item_id = _resolve_indirect(item)
            if isinstance(item_obj, StreamObject):
                try:
                    text = item_obj.get_data().decode("utf-8", errors="ignore")
                except Exception:
                    text = ""
                if text.strip():
                    out.append(
                        TextFragment(
                            text=text,
                            location_type="form_field",
                            page=None,
                            object_id=item_id,
                            source="xfa-stream",
                        )
                    )
            else:
                text = _object_to_text(item_obj)
                if text:
                    out.append(
                        TextFragment(
                            text=text,
                            location_type="form_field",
                            page=None,
                            object_id=item_id,
                            source="xfa-item",
                        )
                    )
    elif isinstance(xfa_obj, StreamObject):
        try:
            text = xfa_obj.get_data().decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        if text.strip():
            out.append(
                TextFragment(
                    text=text,
                    location_type="form_field",
                    page=None,
                    object_id=acro_id,
                    source="xfa-stream-single",
                )
            )


def _scan_form_field_recursive(
    field_ref: object,
    out: list[TextFragment],
    keys_to_check: list[str],
    seen: set[int] | None = None,
) -> None:
    if seen is None:
        seen = set()
    field_obj, field_id = _resolve_indirect(field_ref)
    if field_id is not None:
        if field_id in seen:
            return
        seen.add(field_id)
    if not isinstance(field_obj, DictionaryObject):
        return

    for key in keys_to_check:
        value = field_obj.get(key)
        text = _object_to_text(value)
        if text:
            out.append(
                TextFragment(
                    text=f"{key}: {text}",
                    location_type="form_field",
                    page=None,
                    object_id=field_id,
                    source=f"form:{key}",
                )
            )

    for kid in _iter_array(field_obj.get("/Kids")):
        _scan_form_field_recursive(kid, out, keys_to_check, seen)


def _scan_embedded_files(reader: PdfReader, out: list[TextFragment]) -> None:
    root = reader.trailer.get("/Root")
    root_dict, _ = _resolve_indirect(root)
    if not isinstance(root_dict, DictionaryObject):
        return

    names_dict, _ = _resolve_indirect(root_dict.get("/Names"))
    if not isinstance(names_dict, DictionaryObject):
        return

    embedded, _ = _resolve_indirect(names_dict.get("/EmbeddedFiles"))
    if not isinstance(embedded, DictionaryObject):
        return

    names_arr, _ = _resolve_indirect(embedded.get("/Names"))
    if not isinstance(names_arr, ArrayObject):
        return

    for idx in range(0, len(names_arr), 2):
        name_obj = names_arr[idx]
        spec_obj = names_arr[idx + 1] if idx + 1 < len(names_arr) else None
        name_text = _object_to_text(name_obj)
        spec_dict, spec_id = _resolve_indirect(spec_obj)

        if name_text:
            out.append(
                TextFragment(
                    text=name_text,
                    location_type="embedded_file",
                    page=None,
                    object_id=spec_id,
                    source="embedded:name-tree-key",
                )
            )

        if isinstance(spec_dict, DictionaryObject):
            for key in ["/F", "/UF", "/Desc"]:
                value = spec_dict.get(key)
                text = _object_to_text(value)
                if text:
                    out.append(
                        TextFragment(
                            text=f"{key}: {text}",
                            location_type="embedded_file",
                            page=None,
                            object_id=spec_id,
                            source=f"embedded:{key}",
                        )
                    )


def _scan_all_string_objects(reader: PdfReader, out: list[TextFragment]) -> None:
    visited: set[int] = set()
    root = reader.trailer.get("/Root")
    _walk_objects_for_strings(root, out, visited, active_object_id=None)
    info = reader.trailer.get("/Info")
    _walk_objects_for_strings(info, out, visited, active_object_id=None)


def _walk_objects_for_strings(
    obj: object,
    out: list[TextFragment],
    visited: set[int],
    active_object_id: int | None,
) -> None:
    if obj is None:
        return

    if isinstance(obj, IndirectObject):
        obj_id = obj.idnum
        if obj_id in visited:
            return
        visited.add(obj_id)
        try:
            resolved = obj.get_object()
        except Exception:
            return
        _walk_objects_for_strings(resolved, out, visited, active_object_id=obj_id)
        return

    if isinstance(obj, TextStringObject):
        out.append(
            TextFragment(
                text=str(obj),
                location_type="object_string",
                page=None,
                object_id=active_object_id,
                source="walk:text-string",
            )
        )
        return

    if isinstance(obj, ByteStringObject):
        try:
            decoded = bytes(obj).decode("utf-8", errors="ignore")
        except Exception:
            decoded = repr(obj)
        if decoded.strip():
            out.append(
                TextFragment(
                    text=decoded,
                    location_type="object_string",
                    page=None,
                    object_id=active_object_id,
                    source="walk:byte-string",
                )
            )
        return

    if isinstance(obj, DictionaryObject):
        for key, value in obj.items():
            _walk_objects_for_strings(key, out, visited, active_object_id=active_object_id)
            _walk_objects_for_strings(value, out, visited, active_object_id=active_object_id)
        return

    if isinstance(obj, ArrayObject):
        for item in obj:
            _walk_objects_for_strings(item, out, visited, active_object_id=active_object_id)
        return

    # We intentionally skip scanning all stream bytes here; dedicated handlers
    # cover content streams/XMP/XFA while minimizing noisy binary payloads.


def _iter_array(value: object) -> Iterable[object]:
    resolved, _ = _resolve_indirect(value)
    if isinstance(resolved, ArrayObject):
        return resolved
    return []


def _resolve_indirect(value: object) -> tuple[object, int | None]:
    if isinstance(value, IndirectObject):
        try:
            return value.get_object(), value.idnum
        except Exception:
            return None, value.idnum
    return value, None


def _object_to_text(value: object) -> str:
    if value is None:
        return ""
    resolved, _ = _resolve_indirect(value)
    if isinstance(resolved, TextStringObject):
        return str(resolved)
    if isinstance(resolved, ByteStringObject):
        try:
            return bytes(resolved).decode("utf-8", errors="ignore")
        except Exception:
            return repr(resolved)
    if isinstance(resolved, str):
        return resolved
    if isinstance(resolved, (int, float, bool)):
        return str(resolved)
    return ""


def _walk_string_values(obj: object, depth: int = 0, max_depth: int = 4) -> list[str]:
    if depth > max_depth:
        return []
    out: list[str] = []
    if isinstance(obj, (TextStringObject, str)):
        out.append(str(obj))
        return out
    if isinstance(obj, ByteStringObject):
        try:
            out.append(bytes(obj).decode("utf-8", errors="ignore"))
        except Exception:
            pass
        return out
    if isinstance(obj, IndirectObject):
        try:
            return _walk_string_values(obj.get_object(), depth=depth + 1, max_depth=max_depth)
        except Exception:
            return []
    if isinstance(obj, DictionaryObject):
        for k, v in obj.items():
            out.extend(_walk_string_values(k, depth=depth + 1, max_depth=max_depth))
            out.extend(_walk_string_values(v, depth=depth + 1, max_depth=max_depth))
    elif isinstance(obj, ArrayObject):
        for item in obj:
            out.extend(_walk_string_values(item, depth=depth + 1, max_depth=max_depth))
    return out


def _dedupe_fragments(items: list[TextFragment]) -> list[TextFragment]:
    seen: set[tuple[str, str, int | None, int | None]] = set()
    out: list[TextFragment] = []
    for item in items:
        text = item.text.strip()
        if not text:
            continue
        key = (item.location_type, text, item.page, item.object_id)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out

