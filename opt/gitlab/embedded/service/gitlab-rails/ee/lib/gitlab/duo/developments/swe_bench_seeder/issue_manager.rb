# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      class SweBenchSeeder
        class IssueManager
          def self.create_issue_from_problem_statement(project, user, problem_statement)
            return if problem_statement.blank?

            lines = problem_statement.split("\n")
            title = lines.first.strip
            description = lines[1..].join("\n").strip

            existing_issue = project.issues.find_by_title(title)
            if existing_issue
              puts "Issue '#{title}' already exists. Deleting it..."
              ::Issues::DestroyService.new(container: project, current_user: user).execute(existing_issue)
              puts "Deleted existing issue."
            end

            puts "\nCreating issue from problem statement..."
            puts "Title: #{title}"

            Sidekiq.strict_args!(false)
            result = ::Issues::CreateService.new(
              container: project,
              current_user: user,
              params: {
                title: title,
                description: description
              }
            ).execute

            unless result.success?
              puts "Failed to create issue '#{title}': #{result.errors.join(', ')}"
              return
            end

            issue = result.payload[:issue]
            issue_url = Rails.application.routes.url_helpers.project_issue_url(project, issue)
            puts "Created issue: #{issue_url}"

            issue
          end

          def self.destroy_instance_projects(subgroup, user)
            puts "\nDestroying instance projects in subgroup #{subgroup.full_path}..."
            total_projects_deleted = 0

            mirrors_path = "#{subgroup.full_path}/#{RepositoryManager::MIRRORS_SUBGROUP_PATH}"

            # Iterate through all projects in the subgroup, skipping mirrors
            subgroup.all_projects.find_each do |project|
              if project.full_path.start_with?("#{mirrors_path}/")
                puts "Skipping mirror project: #{project.full_path}"
                next
              end

              # Synchronous destroy so the path is free immediately for re-seeding.
              # Project destruction cascades to issues, so no need to delete them separately.
              ::Projects::DestroyService.new(project, user).execute # rubocop:disable Gitlab/HardDeleteCalls -- Dev-only seeder
              total_projects_deleted += 1
              puts "Deleted project: #{project.full_path}"
            rescue StandardError => e
              puts "Failed to delete project #{project.full_path}: #{e.message}"
            end

            puts "Deleted #{total_projects_deleted} total project(s) from subgroup.\n" if total_projects_deleted > 0
          end
        end
      end
    end
  end
end
