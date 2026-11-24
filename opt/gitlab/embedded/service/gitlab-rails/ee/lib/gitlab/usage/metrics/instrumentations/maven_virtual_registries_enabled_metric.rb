# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class MavenVirtualRegistriesEnabledMetric < GenericMetric
          fallback nil

          value do
            ::VirtualRegistries::Packages::Maven::Registry.exists? &&
              (::VirtualRegistries::Setting.none? || ::VirtualRegistries::Setting.enabled.exists?)
          end
        end
      end
    end
  end
end
