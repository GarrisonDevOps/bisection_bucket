# frozen_string_literal: true

namespace :gitlab do
  namespace :secrets_management do
    desc 'GitLab | Secrets Management | Seed secrets managers and secrets for a root namespace'
    task :seed, [:root_namespace_id] => :gitlab_environment do |_, args|
      abort 'ERROR: This task can only run in the development environment' unless Rails.env.development?

      unless args.root_namespace_id.present?
        abort <<~USAGE
          Usage: rake "gitlab:secrets_management:seed[ROOT_NAMESPACE_ID]"

          Creates subgroups and projects under the given root namespace, provisions
          group and project secrets managers, and populates each with sample secrets.

          Prerequisites:
            - GDK running with EE Ultimate license
            - OpenBao server running
            - Feature flags secrets_manager / group_secrets_manager (enabled automatically)
        USAGE
      end

      begin
        root_id = Integer(args.root_namespace_id)
      rescue ArgumentError
        abort 'ERROR: ROOT_NAMESPACE_ID must be an integer'
      end

      SecretsManagement::RakeTask::Seed.new(root_id).execute
    end
  end
end
