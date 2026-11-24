# frozen_string_literal: true

module EE
  module Gitlab
    module SidekiqMiddleware
      module Client
        extend ActiveSupport::Concern

        class_methods do
          extend ::Gitlab::Utils::Override

          override :configurator
          def configurator
            ->(chain) do
              super.call(chain)
            end
          end
        end
      end

      module Server
        extend ActiveSupport::Concern

        class_methods do
          extend ::Gitlab::Utils::Override

          override :configurator
          def configurator(metrics: true, arguments_logger: true, skip_jobs: true)
            ->(chain) do
              super.call(chain)
              chain.add ::Gitlab::SidekiqMiddleware::SetSession::Server
            end
          end
        end
      end
    end
  end
end
