# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      module Upstreams
        class UpdateService < ::BaseContainerService
          alias_method :upstream, :container

          ALLOWED_ATTRIBUTES = %i[
            name
            description
            url
            username
            password
            cache_validity_hours
            metadata_cache_validity_hours
          ].freeze

          ERRORS = {
            unauthorized: ServiceResponse.error(message: 'Unauthorized', reason: :unauthorized),
            invalid_params: ServiceResponse.error(message: 'Invalid parameters provided', reason: :invalid_params)
          }.freeze

          def initialize(upstream:, current_user: nil, params: {})
            super(container: upstream, current_user: current_user, params: params)
          end

          def execute
            return ERRORS[:unauthorized] unless allowed?
            return ERRORS[:invalid_params] unless valid_params?

            if upstream.update(upstream_params)
              ServiceResponse.success(payload: upstream)
            else
              ServiceResponse.error(message: upstream.errors.to_a)
            end
          end

          private

          def allowed?
            can?(current_user, :update_virtual_registry, upstream)
          end

          def valid_params?
            params.present? && (params.keys & ALLOWED_ATTRIBUTES).any?
          end

          def upstream_params
            params.slice(*ALLOWED_ATTRIBUTES)
          end
        end
      end
    end
  end
end
