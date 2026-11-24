# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    module TrialFormDisplayUtilities
      def format_namespaces_for_selector(namespaces)
        name_counts = namespaces.map(&:name).tally

        namespaces.map do |n|
          display_text = name_counts[n.name] > 1 ? "#{n.name} (/#{n.path})" : n.name
          { text: display_text, value: n.id.to_s }
        end
      end
      # Allow TrialsHelper to use without including the entire module
      # This declaration can be removed with the implementation of
      # https://gitlab.com/gitlab-org/gitlab/-/issues/517153
      # https://gitlab.com/gitlab-org/gitlab/-/issues/517154
      module_function :format_namespaces_for_selector
    end
  end
end
