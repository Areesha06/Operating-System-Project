-- Training workload for sqlite3: create a table and bulk-insert rows in one transaction.
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, customer TEXT, amount REAL);
BEGIN;
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 20000)
INSERT INTO orders(customer, amount) SELECT 'c' || (i % 97), (i * 37) % 1000 / 10.0 FROM n;
COMMIT;
