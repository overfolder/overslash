-- Invariant template_cross_owner (D122 instance_template).
-- An instance whose recorded template tier does not match the template row:
-- a `user` template that is not the instance owner's, or an `org` template
-- that has an owner. resolve_template_source only ever records the owner's
-- own user template or an org template.
SELECT si.org_id AS "org_id!",
       'service_instances' AS "subject_table!",
       si.id AS "subject_id!",
       si.template_source || ' template ' || t.id || ' owned by '
           || COALESCE(t.owner_identity_id::text, 'org')
           || ' (instance owner ' || COALESCE(si.owner_identity_id::text, 'org') || ')' AS "detail!"
FROM service_instances si
JOIN service_templates t ON t.id = si.template_id
WHERE t.org_id = si.org_id
  AND (
      (si.template_source = 'user'
       AND t.owner_identity_id IS DISTINCT FROM si.owner_identity_id)
      OR (si.template_source = 'org' AND t.owner_identity_id IS NOT NULL)
  )
ORDER BY si.org_id, si.id
