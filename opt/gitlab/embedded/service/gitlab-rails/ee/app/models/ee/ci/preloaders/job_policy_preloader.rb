# frozen_string_literal: true

module EE
  module Ci
    module Preloaders
      module JobPolicyPreloader
        extend ::Gitlab::Utils::Override

        private

        # The EE policy and playable? read protected environments (with access
        # levels and approval rules) and deployment approvals, licence permitting.
        override :preload_protected_environments
        def preload_protected_environments
          environments.group_by(&:project_id).each_value do |project_environments|
            next unless licensed?(project_environments.first.project)

            # The preloader's writer does not overwrite an existing memo.
            project_environments.each do |environment|
              environment.clear_memoization(:associated_protected_environments)
            end

            ::Preloaders::Environments::ProtectedEnvironmentPreloader
              .new(project_environments)
              .execute([:deploy_access_levels, :approval_rules])
          end

          # The environment's project is the job's shared instance; deployment.project is not loaded.
          approvable = deployments.select { |deployment| licensed?(deployment.environment.project) }
          return if approvable.empty?

          ActiveRecord::Associations::Preloader.new(records: approvable, associations: :approvals).call
        end

        def licensed?(project)
          project.licensed_feature_available?(:protected_environments)
        end
      end
    end
  end
end
