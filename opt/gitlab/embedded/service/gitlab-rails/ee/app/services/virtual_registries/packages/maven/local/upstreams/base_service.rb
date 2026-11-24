# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      module Local
        module Upstreams
          class BaseService < ::BaseContainerService
            PERMITTED_ATTRIBUTES = %i[
              name
              description
              local_project_id
              local_group_id
              metadata_cache_validity_hours
              cache_validity_hours
            ].freeze

            ERRORS = {
              unauthorized: ServiceResponse.error(message: 'Unauthorized', reason: :unauthorized),
              local_upstream_unauthorized: ServiceResponse.error(
                message: 'Unauthorized to use that project/group for the local upstream',
                reason: :unauthorized
              ),
              empty_params: ServiceResponse.error(message: 'Empty params', reason: :empty_params)
            }.freeze

            def execute
              return ERRORS[:empty_params] if params.compact.empty?
              return ERRORS[:unauthorized] unless allowed?
              return ERRORS[:local_upstream_unauthorized] unless allowed_local_upstream?

              upstream = process_upstream

              if upstream.save
                ServiceResponse.success(payload: upstream)
              else
                ServiceResponse.error(payload: upstream, message: upstream.errors.full_messages,
                  reason: :invalid)
              end
            end

            private

            def upstream_params
              params.slice(*PERMITTED_ATTRIBUTES)
            end

            def allowed_local_upstream?
              allowed_local_project? && allowed_local_group?
            end

            def allowed_local_project?
              return true unless local_project_id

              project = Project.without_deleted
                               .not_hidden
                               .find_by_id(local_project_id)

              can?(current_user, :read_package, project&.packages_policy_subject)
            end

            def allowed_local_group?
              return true unless local_group_id

              group = Group.find_by_id(local_group_id)

              can?(current_user, :read_package_within_public_registries, group&.packages_policy_subject)
            end

            def local_project_id
              params[:local_project_id]
            end

            def local_group_id
              params[:local_group_id]
            end

            def process_upstream
              raise NotImplementedError, "#{self.class} must implement #process_upstream"
            end

            def allowed?
              raise NotImplementedError, "#{self.class} must implement #allowed?"
            end
          end
        end
      end
    end
  end
end
