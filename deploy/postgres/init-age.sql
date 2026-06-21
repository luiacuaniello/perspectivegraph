-- Runs once on first boot of the Postgres+AGE container.
-- Loads the Apache AGE extension and creates the PerspectiveGraph graph.

CREATE EXTENSION IF NOT EXISTS age;

LOAD 'age';
SET search_path = ag_catalog, "$user", public;

-- Create the graph if it does not already exist.
SELECT create_graph('perspective')
WHERE NOT EXISTS (
    SELECT 1 FROM ag_catalog.ag_graph WHERE name = 'perspective'
);
