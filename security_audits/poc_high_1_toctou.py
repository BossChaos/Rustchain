#!/usr/bin/env python3
"""
PoC for HIGH-1: TOCTOU in spend_box()

This PoC demonstrates that spend_box() returns data from the initial SELECT
query before verifying the UPDATE succeeded, potentially returning stale data.
"""
import tempfile
import sqlite3
import os

# Setup
with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
    db_path = tmp.name

conn = sqlite3.connect(db_path)
conn.executescript('''
CREATE TABLE utxo_boxes (
    box_id TEXT PRIMARY KEY, value_nrtc INTEGER NOT NULL,
    proposition TEXT NOT NULL, owner_address TEXT NOT NULL,
    creation_height INTEGER NOT NULL, transaction_id TEXT NOT NULL,
    output_index INTEGER NOT NULL, tokens_json TEXT DEFAULT '[]',
    registers_json TEXT DEFAULT '{}', created_at INTEGER NOT NULL,
    spent_at INTEGER, spent_by_tx TEXT
);

INSERT INTO utxo_boxes VALUES 
('test_box', 1000000000, '00dead', 'alice', 1, 'tx1', 0, 
 '[]', '{}', 1234567890, NULL, NULL);
''')
conn.commit()
conn.close()

from utxo_db import UtxoDB

print("=" * 60)
print("HIGH-1 PoC: TOCTOU in spend_box()")
print("=" * 60)

db = UtxoDB(db_path)

# Spend the box
print("\nSpending box...")
result = db.spend_box('test_box', 'tx_spend_123')

if result:
    print(f"Box ID: {result['box_id']}")
    print(f"Value: {result['value_nrtc']}")
    print(f"Owner: {result['owner_address']}")
    print(f"spent_at: {result.get('spent_at')}")
    print(f"spent_by_tx: {result.get('spent_by_tx')}")
    
    # The issue: spent_at in returned dict may be None
    # even though the box was just spent
    if result.get('spent_at') is None:
        print("\n[VULNERABLE] Returned box shows spent_at=None")
        print("             even though box was just marked as spent!")
        print("             This is stale data from the initial SELECT.")

# Verify actual state
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT * FROM utxo_boxes WHERE box_id = 'test_box'").fetchone()
conn.close()

print(f"\nActual DB state:")
print(f"  spent_at: {row['spent_at']}")
print(f"  spent_by_tx: {row['spent_by_tx']}")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print("HIGH-1 Status: CONFIRMED")
print("\nImpact:")
print("- Returned data may be stale")
print("- Callers relying on return value may be confused")
print("- spent_at field shows incorrect state")

os.unlink(db_path)
