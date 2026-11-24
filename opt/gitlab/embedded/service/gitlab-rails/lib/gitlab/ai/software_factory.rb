# frozen_string_literal: true

module Gitlab
  module Ai
    # The Software Factory is on when `dap_software_factory` is on for the container or for its top-level namespace.
    # A subgroup between them does not count. So one project can turn on the feature without the rest of its group.
    module SoftwareFactory
      def self.enabled?(container)
        Feature.enabled?(:dap_software_factory, container.root_ancestor) ||
          Feature.enabled?(:dap_software_factory, container)
      end
    end
  end
end
