# frozen_string_literal: true

namespace :gitlab do
  namespace :secrets_management do
    desc 'GitLab | Secrets Management | Backfill non-CI API auth (api_jwt) onto existing secrets managers. ' \
      'Optionally pass root_namespace_id to scope to a single customer instead of the whole fleet.'
    task :backfill_api_auth, [:root_namespace_id] => :gitlab_environment do |_, args|
      raw_id = args[:root_namespace_id].presence

      if raw_id && !Integer(raw_id, exception: false)&.positive?
        abort 'ERROR: root_namespace_id must be a positive integer'
      end

      SecretsManagement::RakeTask::BackfillApiAuth.new(root_namespace_id: raw_id&.to_i).execute
    end
  end
end
