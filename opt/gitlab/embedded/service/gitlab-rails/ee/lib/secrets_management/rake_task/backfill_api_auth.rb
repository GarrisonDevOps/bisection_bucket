# frozen_string_literal: true

module SecretsManagement
  module RakeTask
    # Backfills the `api_jwt` mount and `all_api` CEL role onto secrets
    # managers enrolled before non-CI API access (gitlab-org/gitlab#594090)
    # shipped, reusing the same ApiAuthConfigurator the provision flow uses.
    # Idempotent, so it is safe to re-run for SMs that failed a previous
    # attempt.
    #
    # Run by self-managed admins directly, or by SaaS SREs via a change
    # request, on customer request. New enrollments already get this
    # configured at provision time; this task only covers pre-existing ones.
    #
    # Pass root_namespace_id to scope to a single customer's SMs instead of
    # walking the whole fleet, e.g. for a targeted SaaS change request.
    class BackfillApiAuth
      BATCH_SIZE = 500

      def initialize(root_namespace_id: nil)
        @root_namespace_id = root_namespace_id
      end

      def execute
        backfill('project', ProjectSecretsManager, &:project_id)
        backfill('group', GroupSecretsManager, &:group_id)

        puts "\nDone."
      end

      private

      def backfill(label, model_class)
        puts "Backfilling #{label} secrets managers#{scope_description}..."

        relation = model_class.active
        relation = relation.for_root_namespace(@root_namespace_id) if @root_namespace_id

        succeeded = 0
        failed_ids = []

        relation.each_batch(of: BATCH_SIZE) do |batch|
          batch.each do |secrets_manager|
            configure_api_auth(secrets_manager, yield(secrets_manager))
            succeeded += 1
          rescue StandardError => e
            failed_ids << secrets_manager.id
            warn "  [FAILED] #{label} secrets manager (id: #{secrets_manager.id}): #{e.message}"
          end
        end

        summary = "  #{succeeded} succeeded, #{failed_ids.size} failed"
        summary += " (ids: #{failed_ids.join(', ')})" if failed_ids.any?
        puts summary
      end

      def scope_description
        @root_namespace_id ? " under root namespace #{@root_namespace_id}" : ''
      end

      def configure_api_auth(secrets_manager, resource_id)
        ApiAuthConfigurator.new(
          client: client(secrets_manager),
          secrets_manager: secrets_manager,
          resource_id: resource_id
        ).configure
      end

      def client(secrets_manager)
        SecretsManagerClient
          .new(jwt: GlobalSecretsManagerJwt.new.encoded)
          .with_namespace(secrets_manager.full_namespace_path)
      end
    end
  end
end
