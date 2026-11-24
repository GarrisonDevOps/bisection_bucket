# frozen_string_literal: true

namespace :gitlab do
  namespace :ai_catalog do
    desc 'GitLab | AI Catalog | Hydrate database with GitLab-managed agents (Claude Code, Codex)'
    task seed_external_agents: :gitlab_environment do
      Gitlab::Ai::Catalog::ThirdPartyFlows::Seeder.run!
    end

    desc 'GitLab | AI Catalog | Publish skills/<name>/SKILL.md from a project into the catalog'
    task :publish_skills, [:project_path] => :gitlab_environment do |_t, args|
      project_path = args[:project_path]
      abort('Usage: rake "gitlab:ai_catalog:publish_skills[group/project]"') if project_path.blank?

      project = Project.find_by_full_path(project_path)
      abort("Project not found: #{project_path}") unless project

      started = Time.current
      response = ::Ai::Catalog::Skills::PublishService.new(project: project).execute
      elapsed = Time.current - started

      if response.error?
        warn("FAILED (#{response.reason}): #{response.message}")
        exit 1
      end

      # `failed` and `unpublishable` carry a path and its reasons; the rest are bare paths.
      response.payload.each do |bucket, entries|
        puts "#{bucket.to_s.ljust(14)} #{entries.size}"

        entries.each do |entry|
          next puts("  #{entry}") unless entry.is_a?(Hash)

          puts "  #{entry[:path]}"
          entry[:errors].each { |error| puts "    #{error}" }
        end
      end

      puts format('completed in %.3fs', elapsed)
    end
  end
end
