-- Invariant template_cross_org.
-- An instance whose recorded template row lives in another org.
SELECT si.org_id AS "org_id!",
       'service_instances' AS "subject_table!",
       si.id AS "subject_id!",
       'template ' || t.id || ' in org ' || t.org_id AS "detail!"
FROM service_instances si
JOIN service_templates t ON t.id = si.template_id
WHERE t.org_id <> si.org_id
ORDER BY si.org_id, si.id
