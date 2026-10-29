
"""Atomic, bounded-memory SIEM upload ingestion."""

import hashlib
import tempfile

from services.streaming_parser import iter_normalized_events

MAX_UPLOAD_BYTES = 20 * 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024
INSERT_BATCH_SIZE = 250


def import_case_stream(
    *,
    input_stream,
    filename,
    case_id,
    employee_email,
    source_type,
    db,
    upload_model,
    event_model,
):
    """Import all accepted events or none."""

    employee_email = employee_email.strip().lower()

    with tempfile.SpooledTemporaryFile(
        max_size=COPY_CHUNK_BYTES,
        mode="w+b",
    ) as staged:

        digest = hashlib.sha256()
        total_bytes = 0

        while True:
            chunk = input_stream.read(COPY_CHUNK_BYTES)

            if not chunk:
                break

            total_bytes += len(chunk)

            if total_bytes > MAX_UPLOAD_BYTES:
                raise ValueError(
                    "File too large. Maximum upload size is 20 MB."
                )

            digest.update(chunk)
            staged.write(chunk)

        if total_bytes == 0:
            raise ValueError(
                "The selected file is empty."
            )

        sha256 = digest.hexdigest()

        duplicate = upload_model.query.filter_by(
            case_id=case_id,
            sha256=sha256,
        ).first()

        if duplicate:
            raise ValueError(
                "This exact file was already uploaded "
                "to this case."
            )

        imported = 0
        excluded = 0
        batch = []

        try:
            upload = upload_model(
                case_id=case_id,
                filename=filename,
                source_type=source_type,
                sha256=sha256,
                imported_count=0,
                skipped_count=0,
            )

            db.session.add(upload)
            db.session.flush()

            for record in iter_normalized_events(
                staged, filename
            ):
                email = record["user_email"]

                # Preserve existing case identity rules.
                if email and email != employee_email:
                    excluded += 1
                    continue

                record["match_status"] = (
                    "Matched" if email else "Unverified"
                )

                batch.append({
                    "case_id": case_id,
                    "upload_id": upload.id,
                    **record,
                })

                imported += 1

                if len(batch) >= INSERT_BATCH_SIZE:
                    db.session.bulk_insert_mappings(
                        event_model,
                        batch,
                    )
                    batch.clear()

            if imported == 0:
                raise ValueError(
                    "No events can be linked to this employee. "
                    "No changes saved."
                )

            if batch:
                db.session.bulk_insert_mappings(
                    event_model,
                    batch,
                )

            upload.imported_count = imported
            upload.skipped_count = excluded

            db.session.commit()

            return imported, excluded

        except Exception:
            db.session.rollback()
            raise
