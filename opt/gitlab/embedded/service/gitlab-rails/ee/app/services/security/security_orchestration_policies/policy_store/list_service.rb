# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module PolicyStore
      class ListService < BaseService
        # The port speaks offset, not page number: this is the boundary that translates
        # the REST-facing "page N of size M" request into that, so the repository never
        # needs to know what a page is. GraphQL cursors already carry an offset and pass
        # it straight through.
        MAX_PAGE = 1_000
        MAX_OFFSET = ::Gitlab::PolicyStore::Ports::PolicyRepository::MAX_OFFSET

        # The REST/GraphQL-facing sentinel for "no lifecycle_state filter", so a caller
        # can request every policy in one page without a boolean losing that third state.
        ALL_LIFECYCLE_STATES = 'all'

        # A group has at most this many ancestors, so a lookup for its hierarchy never names more namespaces.
        MAX_NAMESPACE_IDS = ::Namespace::NUMBER_OF_ANCESTORS_ALLOWED + 1

        def initialize( # rubocop:disable Metrics/ParameterLists -- each filter is its own optional keyword, so callers name only the ones they use
          container:, current_user:, trigger_type: nil, ids: nil, namespace_ids: nil,
          lifecycle_state: ::Gitlab::PolicyStore::Ports::PolicyRepository::DEFAULT_LIFECYCLE_STATE, page: nil,
          per_page: ::Gitlab::PolicyStore::Ports::PolicyRepository::DEFAULT_PER_PAGE, offset: nil)
          super(container: container, current_user: current_user)

          # A caller passes a page (REST) or an offset (GraphQL cursor), never both:
          # with an offset the page is unknown and the payload reports it as nil.
          raise ArgumentError, 'page and offset are mutually exclusive' if page && offset

          if namespace_ids && !container.is_a?(::Organizations::Organization)
            raise ArgumentError, 'namespace_ids applies only to an organization'
          end

          @trigger_type = trigger_type
          @ids = ids
          @requested_namespace_ids = namespace_ids&.compact&.uniq
          @requested_lifecycle_state = lifecycle_state
          @per_page = per_page.to_i.clamp(1, ::Gitlab::PolicyStore::Ports::PolicyRepository::MAX_PER_PAGE)
          @page = offset.nil? ? (page || 1).to_i.clamp(1, MAX_PAGE) : nil
          @offset = offset.nil? ? (@page - 1) * @per_page : offset.to_i.clamp(0, MAX_OFFSET)
        end

        def execute
          return forbidden_error unless authorized?(:read_govern_policy)
          return experiment_not_active_error unless experiment_active?

          if requested_namespace_ids && requested_namespace_ids.size > MAX_NAMESPACE_IDS
            return too_many_namespaces_error
          end

          return namespace_ids_required_error if unfiltered_lookup_in_shared_organization? && namespace_scoped_trigger?

          result_page = ::Gitlab::PolicyStore.list(
            organization_id: organization.id, trigger_type: trigger_type, namespace_ids: lookup_namespace_ids,
            lifecycle_state: lifecycle_state, ids: ids,
            offset: @offset, per_page: @per_page
          )

          ServiceResponse.success(payload: {
            policies: result_page.items, page: @page, offset: @offset, per_page: result_page.per_page,
            has_next_page: result_page.has_next_page?
          })
        rescue ::Gitlab::PolicyStore::ValidationError => error
          ServiceResponse.error(message: error.message, reason: :invalid)
        end

        private

        attr_reader :trigger_type, :ids, :requested_namespace_ids, :requested_lifecycle_state

        def lookup_namespace_ids
          return readable_namespace_ids if requested_namespace_ids.nil?

          visible_namespace_ids_from(requested_namespace_ids)
        end

        def unfiltered_lookup_in_shared_organization?
          container.is_a?(::Organizations::Organization) && requested_namespace_ids.nil? &&
            organization_shared_across_tenants?
        end

        def namespace_scoped_trigger?
          ::Gitlab::PolicyStore::Triggers::NAMESPACE_SCOPED_TYPES.include?(trigger_type)
        end

        def namespace_ids_required_error
          ServiceResponse.error(
            message: s_('GovernPolicies|namespace_ids is required for this trigger in the default organization'),
            reason: :invalid
          )
        end

        def too_many_namespaces_error
          ServiceResponse.error(
            message: format(s_('GovernPolicies|namespace_ids must contain at most %{limit} namespaces'),
              limit: MAX_NAMESPACE_IDS),
            reason: :invalid
          )
        end

        def lifecycle_state
          requested_lifecycle_state == ALL_LIFECYCLE_STATES ? nil : requested_lifecycle_state
        end
      end
    end
  end
end
