# frozen_string_literal: true

class RemoveHashedRootNamespaceIdFromUsers < Elastic::Migration
  include ::Search::Elastic::MigrationRemoveFieldsHelper

  batched!
  throttle_delay 1.minute

  private

  def index_name
    User.__elasticsearch__.index_name
  end

  def document_type
    'user'
  end

  def field_to_remove
    'hashed_root_namespace_id'
  end
end

RemoveHashedRootNamespaceIdFromUsers.prepend ::Search::Elastic::MigrationObsolete
