# frozen_string_literal: true

module Analytics
  module DevopsAdoption
    module EnabledNamespaces
      class FindOrCreateService
        include CommonMethods

        delegate :authorize!, to: :create_service

        def initialize(current_user:, params: {}, lock: true)
          @params = params
          @current_user = current_user
          @lock = lock
        end

        def execute
          authorize!

          enabled_namespace = find_enabled_namespace

          if enabled_namespace
            ServiceResponse.success(payload: { enabled_namespace: enabled_namespace })
          else
            create_service.execute
          end
        end

        # rubocop: disable CodeReuse/ActiveRecord -- the lookup is on the unique (namespace_id, display_namespace_id) pair and has no model scope
        def find_enabled_namespace
          Analytics::DevopsAdoption::EnabledNamespace.find_by(namespace_id: namespace.id, display_namespace_id: display_namespace&.id)
        end
        # rubocop: enable CodeReuse/ActiveRecord

        def authorize!
          create_service.authorize!
        end

        private

        attr_reader :lock

        def create_service
          @create_service ||= CreateService.new(current_user: current_user, params: params, lock: lock)
        end
      end
    end
  end
end
