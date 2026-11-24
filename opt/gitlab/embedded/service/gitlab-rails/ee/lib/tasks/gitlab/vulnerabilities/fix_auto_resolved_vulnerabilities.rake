# frozen_string_literal: true

namespace :gitlab do
  namespace :vulnerabilities do
    desc 'Fix vulnerabilities affected by https://gitlab.com/gitlab-org/gitlab/-/issues/521907'
    task :fix_auto_resolved_vulnerabilities, [:namespace_id] => :environment do |_, args|
      Vulnerabilities::Rake::FixAutoResolvedVulnerabilities.new(args).execute
    end

    task 'fix_auto_resolved_vulnerabilities:revert', [:namespace_id] => :environment do |_, args|
      Vulnerabilities::Rake::FixAutoResolvedVulnerabilities.new(args, revert: true).execute
    end
  end
end
