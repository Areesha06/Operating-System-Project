-- Held-out workload for sqlite3: different code paths from the training run.
-- Sorting/grouping, index creation, deletes and VACUUM (temp files, truncation, fsync).
CREATE INDEX IF NOT EXISTS idx_customer ON orders(customer);
SELECT customer, COUNT(*), SUM(amount) FROM orders GROUP BY customer ORDER BY SUM(amount) DESC LIMIT 5;
DELETE FROM orders WHERE amount < 20;
VACUUM;
SELECT 'OK', COUNT(*) FROM orders;
