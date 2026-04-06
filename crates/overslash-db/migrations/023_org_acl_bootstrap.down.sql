-- Remove system assets created by bootstrap
DELETE FROM group_grants WHERE group_id IN (SELECT id FROM groups WHERE is_system = true);
DELETE FROM identity_groups WHERE group_id IN (SELECT id FROM groups WHERE is_system = true);
DELETE FROM groups WHERE is_system = true;
DELETE FROM service_instances WHERE is_system = true;

ALTER TABLE groups DROP COLUMN is_system;
ALTER TABLE service_instances DROP COLUMN is_system;
