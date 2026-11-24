# frozen_string_literal: true

module Analytics
  module DevopsAdoption
    module EnabledNamespaces
      module CommonMethods
        include Gitlab::Allowable

        def authorize!
          unless can?(current_user, :manage_devops_adoption_namespaces, namespace)
            raise AuthorizationError.new(self, 'Forbidden')
          end

          unless can?(current_user, :manage_devops_adoption_namespaces, display_namespace || :global)
            raise AuthorizationError.new(self, 'Forbidden')
          end
        end

        private

        attr_reader :current_user, :params

        def namespace
          params[:namespace]
        end

        def display_namespace
          params[:display_namespace]
        end

        # Instance-level rows (no display namespace) are admin-only and stay uncapped.
        def cap_enabled?
          display_namespace.present? && Feature.enabled?(:devops_adoption_enabled_namespaces_cap, display_namespace)
        end

        def cap_lease_key
          "analytics/devops_adoption/enabled_namespaces:#{display_namespace.id}"
        end

        def lock_failed_message
          _("Another request is updating this display namespace's enabled namespaces. Try again.")
        end
      end
    end
  end
end
