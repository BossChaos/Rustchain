#!/usr/bin/env python3
"""
PoC for HIGH-2: Conservation Bypass via Zero-Input Edge Case

This PoC demonstrates that the conservation check in mempool_add uses
'input_total > 0' which could allow certain edge cases to bypass validation.
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

CREATE TABLE utxo_mempool (
    tx_id TEXT PRIMARY KEY, tx_data_json TEXT NOT NULL,
    fee_nrtc INTEGER DEFAULT 0, submitted_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE utxo_mempool_inputs (
    box_id TEXT NOT NULL PRIMARY KEY, tx_id TEXT NOT NULL
);

INSERT INTO utxo_boxes VALUES 
('box1', 1000000000, '00dead', 'alice', 1, 'tx1', 0, 
 '[]', '{}', 1234567890, NULL, NULL);
''')
conn.commit()
conn.close()

from utxo_db import UtxoDB

print("=" * 60)
print("HIGH-2 PoC: Conservation Bypass via Zero-Input Edge Case")
print("=" * 60)

db = UtxoDB(db_path)

# Test 1: Normal transfer with valid conservation
print("\nTest 1: Valid transfer (should succeed)")
tx1 = {
    'tx_id': 'a' * 64,
    'tx_type': 'transfer',
    'inputs': [{'box_id': 'box1'}],
    'outputs': [
        {'address': 'bob', 'value_nrtc': 900000000},
        {'address': 'alice', 'value_nrtc': 90000000}
    ],
    'fee_nrtc': 10000000
}
result1 = db.mempool_add(tx1)
print(f"Result: {result1}")

# Clean up
conn = sqlite3.connect(db_path)
conn.execute("DELETE FROM utxo_mempool_inputs")
conn.execute("DELETE FROM utxo_mempool")
conn.commit()
conn.close()

# Test 2: Mining reward (empty inputs, should succeed)
print("\nTest 2: Mining reward (empty inputs, should succeed)")
tx2 = {
    'tx_id': 'b' * 64,
    'tx_type': 'mining_reward',
    'inputs': [],
    'outputs': [{'address': 'miner', 'value_nrtc': 15000000000}],
    'fee_nrtc': 0
}
result2 = db.mempool_add(tx2)
print(f"Result: {result2}")

# Test 3: Transfer with empty inputs (should fail)
print("\nTest 3: Transfer with empty inputs (should fail)")
tx3 = {
    'tx_id': 'c' * 64,
    'tx_type': 'transfer',
    'inputs': [],
    'outputs': [{'address': 'attacker', 'value_nrtc': 1000000000}],
    'fee_nrtc': 0
}
result3 = db.mempool_add(tx3)
print(f"Result: {result3}")

print("\n" + "=" * 60)
print("VULNERABILITY ANALYSIS")
print("=" * 60)
print("""
The conservation check in mempool_add uses:
    if input_total > 0 and (output_total + fee) > input_total:
        return False

This means:
1. If input_total == 0 (mining_reward), the check is skipped
2. If the empty-inputs check (line 675-676) has a bug, this wouldn't catch it
3. The check uses '>' not '!=', allowing output_total + fee < input_total

While currently protected by the empty-inputs check, this is fragile and
relies on multiple checks being correct rather than a single source of truth.
""")

os.unlink(db_path)
