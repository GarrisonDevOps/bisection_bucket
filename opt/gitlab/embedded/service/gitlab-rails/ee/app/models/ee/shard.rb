# frozen_string_literal: true

module EE
  module Shard # rubocop:disable Gitlab/BoundedContexts -- EE module for existing model
    extend ActiveSupport::Concern

    prepended do
      # `shards` is a gitlab_main_cell_local table and `group_wiki_repositories` is a
      # gitlab_main_org table. Cross-schema foreign keys are not allowed, so we
      # cannot use a DB-level `ON DELETE RESTRICT` FK. A loose FK is also not
      # suitable here because it only supports async cascading deletes, not the
      # RESTRICT action needed to prevent orphaned group_wiki_repositories rows.
      # Therefore, we enforce this constraint at the application level instead.
      has_many :group_wiki_repositories, dependent: :restrict_with_exception # rubocop:disable Cop/ActiveRecordDependent -- See comment above
    end
  end
end
