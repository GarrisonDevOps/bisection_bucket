# frozen_string_literal: true

module EE
  module Gitlab
    module Issuable
      module NamespaceGetter
        extend ::Gitlab::Utils::Override

        override :namespace_id
        def namespace_id
          case issuable
          when Epic
            issuable.group_id
          else
            super
          end
        end
      end
    end
  end
end
