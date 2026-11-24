# frozen_string_literal: true

Gitlab::Seeder.quiet do
  root_namespace = Group.top_level.first
  next warn "\nSkipping orbit_namespace_enrollments seeds: no top-level group available" unless root_namespace

  Analytics::Orbit::NamespaceEnrollment.record_beta(root_namespace.id)

  print '.'
end
