import sqlite3

from app import DATABASE_PATH, calculate_event_hash


def backfill_hash_chain():
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT
                id,
                timestamp,
                username,
                url,
                domain,
                browser,
                severity,
                reason
            FROM web_visits
            ORDER BY id ASC
        """).fetchall()

        previous_hash = "GENESIS"

        for row in rows:
            event_hash = calculate_event_hash(
                row["timestamp"],
                row["username"],
                row["url"],
                row["domain"],
                row["browser"],
                row["severity"],
                row["reason"],
                previous_hash
            )

            connection.execute("""
                UPDATE web_visits
                SET
                    previous_hash = ?,
                    event_hash = ?
                WHERE id = ?
            """, (
                previous_hash,
                event_hash,
                row["id"]
            ))

            previous_hash = event_hash

        connection.commit()

        print(f"Backfilled {len(rows)} events.")
        print("Full hash chain rebuild complete.")


if __name__ == "__main__":
    backfill_hash_chain()
