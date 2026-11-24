# frozen_string_literal: true

class MrDiffApplicationRecord < ApplicationRecord # rubocop:disable Gitlab/BoundedContexts, Gitlab/NamespacedClass -- base class for the mr_diff connection, like SecApplicationRecord
  self.abstract_class = true

  connects_to database: { writing: :mr_diff, reading: :mr_diff } if Gitlab::Database.has_config?(:mr_diff)
end
