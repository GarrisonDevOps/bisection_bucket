# frozen_string_literal: true

module Gitlab
  module Checks
    module Integrations
      class GitGuardianProjectUrlHeader
        def self.build(project)
          ::Gitlab::UrlBuilder.build(project, port: nil, protocol: false).delete_prefix('//')
        end
      end
    end
  end
end
