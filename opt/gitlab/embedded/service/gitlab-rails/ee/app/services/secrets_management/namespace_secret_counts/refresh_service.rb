# frozen_string_literal: true

module SecretsManagement
  module NamespaceSecretCounts
    class RefreshService
      def self.execute_for_namespace_id(namespace_id, current_user_id: nil)
        namespace = ::Namespace.find_by_id(namespace_id)
        return ServiceResponse.success(payload: { skipped: :missing_namespace }) unless namespace

        current_user = ::User.find_by_id(current_user_id) if current_user_id
        current_user ||= system_user_for(namespace)

        new(namespace, current_user: current_user).execute
      end

      def self.system_user_for(namespace)
        case namespace
        when ::Group
          namespace.first_owner
        when ::Namespaces::ProjectNamespace
          namespace.project&.first_owner
        end
      end
      private_class_method :system_user_for

      def initialize(namespace, current_user: nil)
        @namespace = namespace
        @current_user = current_user
      end

      def execute
        if secrets_manager.blank? || !secrets_manager.active?
          delete_namespace_count
          ServiceResponse.success(payload: { removed: true })
        else
          count = fetch_count
          upsert_count(count)
          ServiceResponse.success(payload: { count: count })
        end
      end

      private

      attr_reader :namespace, :current_user

      def secrets_manager
        return @secrets_manager if defined?(@secrets_manager)

        @secrets_manager =
          case namespace
          when ::Group
            namespace.secrets_manager
          when ::Namespaces::ProjectNamespace
            namespace.project&.secrets_manager
          end
      end

      def fetch_count
        case namespace
        when ::Group
          GroupSecretsCountService.new(namespace, current_user).execute
        when ::Namespaces::ProjectNamespace
          ProjectSecretsCountService.new(namespace.project, current_user).execute
        end
      end

      def upsert_count(count)
        NamespaceSecretCount.upsert(
          {
            namespace_id: namespace.id,
            root_namespace_id: namespace.root_ancestor.id,
            count: count
          },
          unique_by: :namespace_id,
          update_only: %i[count root_namespace_id]
        )
      end

      # `namespace_id` is the primary key of `namespace_secret_counts`, so at
      # most one row matches. `delete_all` is used (rather than a per-record
      # destroy) because there are no callbacks or dependent associations to
      # run, and it stays a no-op when the row is already absent.
      def delete_namespace_count
        NamespaceSecretCount.for_namespace_id(namespace.id).delete_all
      end
    end
  end
end
