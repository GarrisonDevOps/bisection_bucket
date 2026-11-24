# frozen_string_literal: true

# Existing seeded work items are kept; set RESET=1 to recreate them.
namespace :gitlab do
  namespace :seed do
    desc 'GitLab | Seed | Seed work items with workplans and readiness scores'
    task :workplans, [:project_path, :username] => :gitlab_environment do |_t, args|
      abort('This task can only run in development or test.') unless Gitlab.dev_or_test_env?

      usage = 'Usage: rake "gitlab:seed:workplans[group/project,username]"'
      abort(usage) if args.project_path.blank? || args.username.blank?

      project = Project.find_by_full_path(args.project_path)
      abort("Project not found: #{args.project_path}") unless project

      user = User.find_by_username(args.username)
      abort("User not found: #{args.username}") unless user

      results = Gitlab::Seeders::WorkItems::Workplans.new(
        project: project,
        user: user,
        reset: Gitlab::Utils.to_boolean(ENV['RESET'], default: false)
      ).seed!

      # Local storage is relative to this checkout, so a run from another worktree hides every plan from GDK.
      unless WorkItems::AgentPlanContentUploader.object_store_enabled?
        puts "Workplan content stored in #{WorkItems::AgentPlanContentUploader.root}"
      end

      results.each do |result|
        state = result[:created] ? 'created' : 'exists '
        puts "#{state} #{Gitlab::UrlBuilder.build(result[:work_item])}  #{result[:work_item].title}"
      end
    end
  end
end
