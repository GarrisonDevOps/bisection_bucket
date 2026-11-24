# frozen_string_literal: true

class CreateGroupsIndex < Elastic::Migration
  include ::Search::Elastic::MigrationCreateIndexHelper

  retry_on_failure

  def document_type
    :group
  end

  def target_class
    ::Group
  end
end
