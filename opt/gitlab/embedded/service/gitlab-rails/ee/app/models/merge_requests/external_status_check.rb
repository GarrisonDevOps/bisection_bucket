# frozen_string_literal: true

module MergeRequests
  class ExternalStatusCheck < ApplicationRecord
    self.table_name = 'external_status_checks'

    include Auditable
    include Gitlab::EncryptedAttribute
    include Gitlab::Utils::StrongMemoize

    attr_encrypted :shared_secret,
      mode: :per_attribute_iv,
      algorithm: 'aes-256-cbc',
      key: :db_key_base_32

    scope :with_api_entity_associations, -> { preload(:protected_branches) }
    scope :for_all_branches, -> { where.missing(:protected_branches) }

    belongs_to :project
    has_and_belongs_to_many :protected_branches,
      after_add: :audit_protected_branch_add, after_remove: :audit_protected_branch_remove
    after_create_commit :audit_creation
    after_destroy_commit :audit_deletion
    validates :external_url, presence: true, uniqueness: { scope: :project_id }, addressable_url: true
    validates :name, uniqueness: { scope: :project_id }, presence: true
    # Shared secrets are user-provided HMAC secrets for webhook signatures.
    # A limit of 255 is consistent with other similar columns.
    validates :shared_secret, length: { maximum: 255 }, if: :shared_secret_changed?
    validate :protected_branches_must_belong_to_project_or_group_hierarchy

    def async_execute(data)
      target_branch = data.dig(:object_attributes, :target_branch)

      if target_branch.nil?
        Gitlab::AppLogger.warn(
          message: 'ExternalStatusCheck#async_execute called with missing target_branch',
          external_status_check_id: id,
          project_id: project_id
        )

        return
      end

      return unless applies_to_branch?(target_branch)

      ApprovalRules::ExternalApprovalRulePayloadWorker.perform_async(self.id, payload_data(data))
    end

    # Returns true when this check should be evaluated for `branch`.
    #
    # Mirrors the wildcard-aware semantics used by ApprovalProjectRule:
    # an empty `protected_branches` association means "all branches";
    # otherwise at least one protected_branch must glob-match `branch`
    # via `ProtectedBranch.matching` (which delegates to `RefMatcher`).
    #
    # @note This is a pure filter; callers must enforce
    #   the `:external_status_checks` license and the
    #   `:read_external_status_check_response` policy.
    def applies_to_branch?(branch)
      return true if protected_branches.empty?
      return protected_branch_matches?(branch, protected_branches) if protected_branches.loaded?

      protected_branches.matching(branch).any?
    end

    def status(merge_request, sha)
      last_response = response_for(merge_request, sha)

      return 'pending' unless last_response

      last_response.status
    end

    def failed?(merge_request)
      status(merge_request, merge_request.diff_head_sha) == 'failed'
    end

    def response_for(merge_request, sha)
      merge_request.status_check_responses.order(id: :desc).find_by(external_status_check: self, sha: sha)
    end

    def to_h
      {
        id: self.id,
        name: self.name,
        external_url: self.external_url
      }
    end

    def audit_protected_branch_add(model)
      message = "Added #{model.class.downcase_humanized_name} #{model.name} to #{self.name} status check"
      message += " and removed all other branches from status check" if protected_branches.count == 1
      push_audit_event(message)
    end

    def audit_creation
      message = "Added #{self.name} status check"
      message += if protected_branches.empty?
                   " with all branches"
                 else
                   " with protected branch(es) #{self.protected_branches_names}"
                 end

      push_audit_event(message)
    end

    def audit_deletion
      push_audit_event("Removed #{self.name} status check")
    end

    def audit_protected_branch_remove(model)
      message = if protected_branches.empty?
                  "Added all branches to #{self.name} status check"
                else
                  "Removed #{model.class.downcase_humanized_name} #{model.name} from #{self.name} status check"
                end

      push_audit_event(message)
    end

    def hmac?
      shared_secret.present?
    end

    private

    def protected_branch_matches?(branch, protected_refs)
      strong_memoize_with(:protected_branch_matches, branch, protected_refs) do
        ProtectedBranch.matching(branch, protected_refs: protected_refs).any?
      end
    end

    def protected_branches_names
      self.protected_branches.pluck(:name).join(', ')
    end

    def payload_data(merge_request_hook_data)
      merge_request_hook_data.merge(external_approval_rule: self.to_h)
    end

    def protected_branches_must_belong_to_project_or_group_hierarchy
      errors.add(:base, 'all protected branches must exist within the project') unless protected_branches.all? { |b| project.all_protected_branches.include?(b) }
    end
  end
end

::MergeRequests::ExternalStatusCheck.prepend_mod
