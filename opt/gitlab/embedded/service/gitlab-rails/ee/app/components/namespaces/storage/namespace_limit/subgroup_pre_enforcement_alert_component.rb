# frozen_string_literal: true

module Namespaces
  module Storage
    module NamespaceLimit
      class SubgroupPreEnforcementAlertComponent < PreEnforcementAlertComponent
        extend ::Gitlab::Utils::Override

        private

        override :paragraph_1_extra_message
        def paragraph_1_extra_message
          safe_format(
            s_("UsageQuota|The %{strong_start}%{context_name}%{strong_end} group will be affected by this. "),
            strong_tags.merge(context_name: context.name)
          )
        end
      end
    end
  end
end
