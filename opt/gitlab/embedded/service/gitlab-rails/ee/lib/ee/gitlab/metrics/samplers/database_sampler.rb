# frozen_string_literal: true

module EE
  module Gitlab
    module Metrics
      module Samplers
        module DatabaseSampler
          extend ::Gitlab::Utils::Override

          private

          override :host_metrics
          def host_metrics
            super.concat(geo_connection_metrics)
          end

          def geo_connection_metrics
            return [] unless ::Geo::TrackingBase.connected?

            build_metrics(labels_for_class(::Geo::TrackingBase), ::Geo::TrackingBase.connection_pool.stat)
          end

          override :extended_host_metrics
          def extended_host_metrics
            super.concat(geo_extended_connection_metrics)
          end

          def geo_extended_connection_metrics
            return [] unless ::Geo::TrackingBase.connected?

            build_extended_metrics(
              labels_for_class(::Geo::TrackingBase),
              ::Geo::TrackingBase.connection_pool.extended_stat
            )
          end
        end
      end
    end
  end
end
