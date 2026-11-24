# frozen_string_literal: true

Gitlab::Seeder.quiet do
  # Seed ASCP scans for projects that have a repository
  Project.take(10).select { |project| !project.empty_repo? }.take(3).each do |project|
    next unless project.repository.head_commit

    commit_sha = project.repository.head_commit.id

    # Create a full scan
    full_scan = Security::Ascp::Scan.create!(
      project: project,
      scan_sequence: 1,
      scan_type: 'full',
      commit_sha: commit_sha
    )

    # Create an incremental scan referencing the full scan
    Security::Ascp::Scan.create!(
      project: project,
      scan_sequence: 2,
      scan_type: 'incremental',
      commit_sha: commit_sha,
      base_scan: full_scan,
      base_commit_sha: commit_sha
    )

    print '.'
  end
end
