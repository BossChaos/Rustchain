#!/usr/bin/env python3
"""
PoC for CRITICAL-1: mempool_add() Undefined Variable (manage_tx)

This PoC demonstrates that the mempool_add function references an undefined
variable 'manage_tx' which causes NameError exceptions that are silently caught,
preventing proper rollback execution.
"""
import sys
import tempfile
import sqlite3
import os

# Setup test database
with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
    db_path = tmp.name

conn = sqlite3.connect(db_path)
conn.executescript('''
CREATE TABLE utxo_boxes (
    box_id TEXT PRIMARY KEY,
    value_nrtc INTEGER NOT NULL,
    proposition TEXT NOT NULL,
    owner_address TEXT NOT NULL,
    creation_height INTEGER NOT NULL,
    transaction_id TEXT NOT NULL,
    output_index INTEGER NOT NULL,
    tokens_json TEXT DEFAULT '[]',
    registers_json TEXT DEFAULT '{}',
    created_at INTEGER NOT NULL,
    spent_at INTEGER,
    spent_by_tx TEXT
);

CREATE TABLE utxo_mempool (
    tx_id TEXT PRIMARY KEY,
    tx_data_json TEXT NOT NULL,
    fee_nrtc INTEGER DEFAULT 0,
    submitted_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE utxo_mempool_inputs (
    box_id TEXT NOT NULL PRIMARY KEY,
    tx_id TEXT NOT NULL
);

INSERT INTO utxo_boxes VALUES 
('box1', 1000000000, '00deadbeef', 'alice', 1, 'tx1', 0, '[]', '{}', 1234567890, NULL, NULL);
''')
conn.commit()
conn.close()

# Import after creating DB
from utxo_db import UtxoDB

# Track NameError occurrences
nameerror_count = [0]

def trace_calls(frame, event, arg):
    if event == 'exception':
        exc_type, exc_value, _ = arg
        if exc_type == NameError and 'manage_tx' in str(exc_value):
            nameerror_count[0] += 1
            print(f"[VULNERABILITY CONFIRMED] NameError #{nameerror_count[0]}: {exc_value}")
    return trace_calls

sys.settrace(trace_calls)

db = UtxoDB(db_path)

# Test 1: Add valid transaction
print("=" * 60)
print("Test 1: Adding valid transaction")
print("=" * 60)
tx1 = {
    'tx_id': 'a' * 64,
    'tx_type': 'transfer',
    'inputs': [{'box_id': 'box1'}],
    'outputs': [{'address': 'bob', 'value_nrtc': 900000000}],
    'fee_nrtc': 100000000
}
result1 = db.mempool_add(tx1)
print(f"Result: {result1}")

# Test 2: Attempt double-spend (triggers manage_tx check)
print("\n" + "=" * 60)
print("Test 2: Double-spend attempt (triggers manage_tx NameError)")
print("=" * 60)
tx2 = {
    'tx_id': 'b' * 64,
    'tx_type': 'transfer',
    'inputs': [{'box_id': 'box1'}],  # Same input
    'outputs': [{'address': 'eve', 'value_nrtc': 900000000}],
    'fee_nrtc': 100000000
}
result2 = db.mempool_add(tx2)
print(f"Result: {result2}")

# Test 3: Negative fee (triggers another manage_tx check)
print("\n" + "=" * 60)
print("Test 3: Negative fee (triggers manage_tx NameError)")
print("=" * 60)
tx3 = {
    'tx_id': 'c' * 64,
    'tx_type': 'transfer',
    'inputs': [{'box_id': 'box1'}],
    'outputs': [{'address': 'bob', 'value_nrtc': 900000000}],
    'fee_nrtc': -100  # Negative fee
}
result3 = db.mempool_add(tx3)
print(f"Result: {result3}")

sys.settrace(None)

# Summary
print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Total NameError occurrences: {nameerror_count[0]}")
print(f"CRITICAL-1 Status: {'CONFIRMED' if nameerror_count[0] > 0 else 'NOT REPRODUCED'}")
print("\nImpact:")
print("- Rollback logic fails silently due to NameError")
print("- Database may be left in inconsistent state")
print("- Mempool pollution possible")

# Cleanup
os.unlink(db_path)
